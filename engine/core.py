import json, os, re, sqlite3, tempfile, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PROGRAMS = BASE / "programs"
STATE = BASE / "state"
REPORTS = BASE / "reports"
CATEGORIES = [
    ("access-control", "IDOR/BOLA on two owned test objects", "GET", 2),
    ("authentication", "Own-account session invalidation review", "GET", 2),
    ("injection", "Non-destructive input validation review", "GET", 1),
    ("ssrf", "Review server-side URL input without internal-address probes", "GET", 1),
    ("misconfiguration", "Security header and CORS review", "GET", 1),
    ("integrity", "Client-side dependency integrity review", "GET", 1),
    ("logging", "Confirm authorized audit events with owner-provided logs", "NONE", 0),
    ("business-logic", "Owned-resource workflow authorization review", "GET", 2),
]
def ensure():
    for p in (PROGRAMS, STATE, REPORTS):
        p.mkdir(parents=True, exist_ok=True)
        p.chmod(0o700)
def valid_name(name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", name):
        raise ValueError("Program name must be 1–48 letters, numbers, _ or -")
    return name
def valid_domain(domain):
    d=domain.lower().strip().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", d):
        raise ValueError("Invalid domain")
    return d
def profile_path(name):
    return PROGRAMS / (valid_name(name)+".json")
def save_json(path, data):
    ensure()
    fd, tmp = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
def init(name, domain):
    name=valid_name(name); domain=valid_domain(domain)
    path=profile_path(name)
    if path.exists(): raise ValueError("Profile already exists; will not overwrite")
    save_json(path, {
        "program_name": name, "policy_url": "", "policy_reviewed": False,
        "ai_allowed": False, "passive_allowed": False,
        "allowed_domains": [domain], "excluded_domains": [],
        "notes": "Review the real program policy before enabling any network access.",
        "max_ct_results": 100, "passive_timeout_seconds": 10
    })
    return path
def load(name):
    p=profile_path(name)
    data=json.loads(p.read_text())
    if data.get("program_name") != valid_name(name): raise ValueError("Invalid profile")
    for k in ("policy_reviewed", "ai_allowed", "passive_allowed"):
        if type(data.get(k)) is not bool: raise ValueError("Policy flag invalid: "+k)
    domains=data.get("allowed_domains")
    if not isinstance(domains,list) or not domains: raise ValueError("No allowed domains")
    data["allowed_domains"]=[valid_domain(x) for x in domains]
    data["excluded_domains"]=[valid_domain(x) for x in data.get("excluded_domains",[])]
    return data
def policy_ok(data):
    return all(data.get(x) is True for x in ("policy_reviewed","ai_allowed","passive_allowed"))
def in_scope(host, data):
    try: host=valid_domain(host)
    except (ValueError,AttributeError): return False
    allowed=any(host==d or host.endswith("."+d) for d in data["allowed_domains"])
    excluded=any(host==d or host.endswith("."+d) for d in data["excluded_domains"])
    return allowed and not excluded
def db(name):
    ensure()
    conn=sqlite3.connect(STATE/(valid_name(name)+".sqlite"))
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS hosts (host TEXT PRIMARY KEY, source TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS suggestions (id INTEGER PRIMARY KEY, category TEXT, title TEXT, method TEXT, max_requests INTEGER, status TEXT DEFAULT 'pending')")
    conn.commit()
    return conn

def managed_db(name):
    """Commit/rollback like sqlite3 context manager, then close."""
    from contextlib import contextmanager

    @contextmanager
    def connection():
        conn = db(name)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    return connection()

def getmeta(conn, key, default=None):
    row=conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default
def setmeta(conn,key,value):
    conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",(key,str(value)))
    conn.commit()
def ct_fetch(domain, timeout, max_results):
    # One public CT endpoint; no target probing or redirects.
    from urllib.parse import urlencode
    url="https://crt.sh/?" + urlencode({"q":"%."+domain,"output":"json"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs): return None
    opener=urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url,headers={"User-Agent":"CyberParthaBOT/2.0 passive-research"}),timeout=timeout) as r:
        if r.status != 200: raise RuntimeError("CT source unavailable")
        content=r.read(2_000_001)
        if len(content)>2_000_000: raise RuntimeError("CT response too large")
    records=json.loads(content)
    if not isinstance(records,list): raise RuntimeError("Invalid CT response")
    hosts=[]
    for record in records:
        if not isinstance(record,dict): continue
        for raw in str(record.get("name_value","")).splitlines():
            host=raw.strip().lower().removeprefix("*.")
            if host and host not in hosts: hosts.append(host)
            if len(hosts)>=max_results: return hosts
    return hosts
def recon(name):
    data=load(name)
    if not policy_ok(data):
        raise PermissionError("Policy/AI/passive permissions not explicitly enabled; no network request sent")
    with managed_db(name) as conn:
        if getmeta(conn,"paused","0")=="1": return "Paused; no request sent"
        if getmeta(conn,"recon_done","0")=="1": return "Already completed; resume without repeating"
        max_results=min(max(int(data.get("max_ct_results",100)),1),200)
        timeout=min(max(int(data.get("passive_timeout_seconds",10)),1),20)
        # Query each allowed domain once; checkpoint each domain for pause/resume.
        for domain in data["allowed_domains"]:
            if getmeta(conn,"paused","0")=="1": break
            if getmeta(conn,"ct_done:"+domain,"0")=="1": continue
            hosts=ct_fetch(domain,timeout,max_results)
            for host in hosts:
                if in_scope(host,data):
                    conn.execute("INSERT OR IGNORE INTO hosts VALUES (?,?)",(host,"certificate-transparency"))
            conn.commit()
            setmeta(conn,"ct_done:"+domain,"1")
        if all(getmeta(conn,"ct_done:"+d,"0")=="1" for d in data["allowed_domains"]):
            setmeta(conn,"recon_done","1")
        count=conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    return f"Passive CT recon checkpoint saved; {count} scoped hosts"
def suggestions(name):
    data=load(name)
    if not data["policy_reviewed"]: raise PermissionError("Review program policy first")
    with managed_db(name) as conn:
        if getmeta(conn,"paused","0")=="1": return "Paused"
        for category,title,method,budget in CATEGORIES:
            if not conn.execute("SELECT 1 FROM suggestions WHERE category=?",(category,)).fetchone():
                conn.execute("INSERT INTO suggestions (category,title,method,max_requests) VALUES (?,?,?,?)",(category,title,method,budget))
        conn.commit()
        return conn.execute("SELECT COUNT(*) FROM suggestions").fetchone()[0]
def next_test(name):
    with managed_db(name) as conn:
        row=conn.execute("SELECT id,category,title,method,max_requests FROM suggestions WHERE status='pending' ORDER BY id LIMIT 1").fetchone()
        return row
def approve(name):
    data=load(name)
    if not data["policy_reviewed"]: raise PermissionError("Policy not reviewed")
    with managed_db(name) as conn:
        if getmeta(conn,"paused","0")=="1": raise PermissionError("Paused")
        row=next_test(name)
        if not row: return "No pending suggestion"
        ident,category,title,method,budget=row
        print(f"Proposed test #{ident}: {title}\nCategory: {category}\nMethod: {method}\nMaximum requests: {budget}")
        print("Approval is for planning only. This v2 has NO active network execution adapter.")
        if input("Type YES to mark this plan approved: ") != "YES": return "Denied"
        conn.execute("UPDATE suggestions SET status='approved' WHERE id=? AND status='pending'",(ident,))
        conn.commit()
        return f"Plan #{ident} approved (no active request executed)"
def complete(name, outcome):
    if outcome not in ("validated","not-reproducible","skipped","blocked"): raise ValueError("Invalid outcome")
    with managed_db(name) as conn:
        row=conn.execute("SELECT id FROM suggestions WHERE status='approved' ORDER BY id LIMIT 1").fetchone()
        if not row: return "No approved plan"
        conn.execute("UPDATE suggestions SET status=? WHERE id=?",(outcome,row[0]))
        conn.commit()
        return f"Plan #{row[0]} marked {outcome} (user assertion; not independently verified)"
def report(name):
    data=load(name)
    with managed_db(name) as conn:
        hosts=[r[0] for r in conn.execute("SELECT host FROM hosts ORDER BY host LIMIT 200")]
        plans=[{"id":r[0],"category":r[1],"title":r[2],"status":r[3]} for r in conn.execute("SELECT id,category,title,status FROM suggestions ORDER BY id")]
    path=REPORTS/(valid_name(name)+"-report.json")
    save_json(path,{"program":name,"generated_at":datetime.now(timezone.utc).isoformat(),
                    "policy_reviewed":data["policy_reviewed"],"passive_hosts":hosts,
                    "test_plans":plans,"note":"No active tests were executed by this tool. Plan outcomes are user-entered."})
    return path
