"""Phase 2: offline policy review and bounded public-source passive collection."""
import hashlib, json, re, urllib.request
from urllib.parse import urlencode, urlsplit
from . import core

SOURCES = ('ct', 'wayback')

def policy_review(name):
    d = core.load(name)
    checks = {
      'policy_url_present': d.get('policy_url','').startswith('https://'),
      'policy_human_reviewed': d['policy_reviewed'],
      'ai_discovery_explicitly_allowed': d['ai_allowed'],
      'passive_automation_explicitly_allowed': d['passive_allowed'],
      'scope_defined': bool(d['allowed_domains']),
      'exclusions_reviewed': isinstance(d['excluded_domains'],list),
    }
    return {'program':name,'checks':checks,'passive_ready':all(checks.values()),
      'note':'This is a checklist of operator assertions, not automated policy verification.'}

def fetch_wayback(domain,timeout,limit):
    # Query only a fixed public archive API, never the target host.
    url='https://web.archive.org/cdx/search/cdx?'+urlencode({
      'url':domain+'/*','output':'json','filter':'statuscode:200',
      'collapse':'urlkey','fl':'original','limit':str(limit)})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**kw): return None
    opener=urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'CyberParthaBOT/3.0 research'}),timeout=timeout) as r:
        if r.status!=200: raise RuntimeError('Archive API unavailable')
        content=r.read(1_000_001)
        if len(content)>1_000_000: raise RuntimeError('Archive response too large')
    records=json.loads(content)
    if not isinstance(records,list): raise RuntimeError('Invalid archive response')
    hosts=[]
    for row in records[1:]:
        if not isinstance(row,list) or not row or not isinstance(row[0],str):continue
        try:
            parsed=urlsplit(row[0]); host=parsed.hostname
            if parsed.scheme not in ('http','https') or not host:continue
            host=core.valid_domain(host)
        except (ValueError,TypeError): continue
        if host not in hosts:hosts.append(host)
        if len(hosts)>=limit:break
    return hosts

def collect(name,source='all'):
    d=core.load(name)
    if not policy_review(name)['passive_ready']:
        raise PermissionError('Policy URL, human review, AI and passive permissions must all be explicitly set; no traffic sent')
    if source not in SOURCES+('all',): raise ValueError('Unknown source')
    sources=SOURCES if source=='all' else (source,)
    limit=min(max(int(d.get('max_ct_results',100)),1),200)
    timeout=min(max(int(d.get('passive_timeout_seconds',10)),1),20)
    # Scope + source configuration fingerprint invalidates previous checkpoints.
    fingerprint=hashlib.sha256(json.dumps({
      'allowed':d['allowed_domains'],'excluded':d['excluded_domains'],
      'policy_url':d['policy_url'],'policy_reviewed':d['policy_reviewed'],
      'ai_allowed':d['ai_allowed'],'passive_allowed':d['passive_allowed']},sort_keys=True).encode()).hexdigest()
    with core.managed_db(name) as conn:
        if core.getmeta(conn,'paused','0')=='1': return 'Paused; no network traffic'
        if core.getmeta(conn,'phase2_fingerprint')!=fingerprint:
            conn.execute("DELETE FROM meta WHERE key LIKE 'phase2_done:%'")
            conn.execute('DELETE FROM hosts')
            conn.commit()
            core.setmeta(conn,'phase2_fingerprint',fingerprint)
        tasks=0
        for domain in d['allowed_domains']:
            for src in sources:
                key='phase2_done:'+src+':'+domain
                if core.getmeta(conn,key,'0')=='1':continue
                if core.getmeta(conn,'paused','0')=='1':break
                found=core.ct_fetch(domain,timeout,limit) if src=='ct' else fetch_wayback(domain,timeout,limit)
                for host in found:
                    if core.in_scope(host,d):
                        conn.execute('INSERT OR IGNORE INTO hosts VALUES (?,?)',(host,src))
                conn.commit()
                core.setmeta(conn,key,'1')
                tasks+=1
        count=conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
    return f'Phase 2 passive collection: {tasks} new source/domain tasks, {count} in-scope hostnames; no target-host requests'
