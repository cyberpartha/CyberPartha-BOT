import argparse
from engine import core, intelligence, phase2, phase3, phase4, phase5

def main():
    p=argparse.ArgumentParser(description="CyberPartha BOT v3 Phase 5 — policy-gated research planner")
    sub=p.add_subparsers(dest="command",required=True)
    init=sub.add_parser("init");init.add_argument("--name",required=True);init.add_argument("--domain",required=True)
    for cmd in ("policy","recon","suggestions","next","approve","pause","resume","status","report"):
        q=sub.add_parser(cmd);q.add_argument("--program",required=True)
    done=sub.add_parser("complete");done.add_argument("--program",required=True);done.add_argument("--outcome",choices=["validated","not-reproducible","skipped","blocked"],required=True)
    obs=sub.add_parser("analyze")
    obs.add_argument("--program",required=True)
    obs.add_argument("--observation",required=True,help="Sanitized endpoint/parameter labels only; NO secrets")
    check=sub.add_parser("policy-check");check.add_argument("--program",required=True)
    collect=sub.add_parser("collect");collect.add_argument("--program",required=True)
    collect.add_argument("--source",choices=["ct","wayback","all"],default="all")
    inventory=sub.add_parser("endpoint-analyze")
    inventory.add_argument("--program",required=True)
    inventory.add_argument("--input",required=True,help="Local JSON list of sanitized endpoint metadata")
    for command in ("local-plan", "local-approve", "local-execute"):
        q=sub.add_parser(command); q.add_argument("--program",required=True); q.add_argument("--url",required=True)
        if command=="local-execute": q.add_argument("--token",required=True)
    local_enable=sub.add_parser("local-enable"); local_enable.add_argument("--program",required=True)
    q=sub.add_parser("phase5-report"); q.add_argument("--program",required=True)
    sub.add_parser("test")
    args=p.parse_args()
    try:
        c=args.command
        if c=="init": print("Created disabled profile:",core.init(args.name,args.domain))
        elif c=="test":
            import unittest
            result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover("tests"))
            return 0 if result.wasSuccessful() else 1
        elif c=="analyze":
            data=core.load(args.program)
            if not data["policy_reviewed"]:
                raise PermissionError("Policy review required before test planning")
            matches=intelligence.classify(args.observation)
            if not matches:
                print("No evidence-matched checks; no findings asserted")
            else:
                with core.db(args.program) as conn:
                    for item in matches:
                        exists=conn.execute("SELECT 1 FROM suggestions WHERE category=?",(item["category"],)).fetchone()
                        if not exists:
                            conn.execute("INSERT INTO suggestions (category,title,method,max_requests) VALUES (?,?,?,?)",
                                (item["category"],item["title"],"PLAN ONLY",item["max_requests"]))
                    conn.commit()
                print("Hypotheses queued (NOT vulnerabilities, NOT executed):",len(matches))
                for item in matches: print("-",item["category"],":",item["title"])
        elif c=="local-enable":
            print("Only enable for a localhost service that you own and control.")
            answer=input("Type I OWN THIS LOCAL LAB to enable: ")
            print(phase4.enable(args.program,answer))
        elif c=="phase5-report":
            print("Offline reports:", phase5.generate(args.program))
        elif c=="local-plan":
            import json
            print(json.dumps(phase4.plan(args.program,args.url),indent=2))
        elif c=="local-approve":
            import json
            print(json.dumps(phase4.plan(args.program,args.url),indent=2))
            print("Local lab only. Confirm that you own/control the service.")
            answer=input("Type YES to approve this ONE local GET: ")
            print(json.dumps(phase4.approve(args.program,args.url,answer),indent=2))
        elif c=="local-execute":
            import json
            print(json.dumps(phase4.execute(args.program,args.url,args.token),indent=2))
        elif c=="endpoint-analyze":
            path,count,hypotheses=phase3.analyze_file(args.program,args.input)
            print(f"Offline endpoint analysis: {count} unique endpoints, {hypotheses} hypotheses (NOT findings)")
            print("Sanitized report:",path)
        elif c=="policy-check":
            import json
            print(json.dumps(phase2.policy_review(args.program),indent=2))
        elif c=="collect": print(phase2.collect(args.program,args.source))
        elif c=="policy":
            d=core.load(args.program)
            print("Program:",d["program_name"],"\nPolicy:",d["policy_url"] or "NOT PROVIDED")
            print("Reviewed:",d["policy_reviewed"],"| AI permitted:",d["ai_allowed"],"| Passive permitted:",d["passive_allowed"])
            print("Allowed:",d["allowed_domains"],"\nExcluded:",d["excluded_domains"])
            print("Passive recon unlocked:",core.policy_ok(d))
        elif c=="recon": print(core.recon(args.program))
        elif c=="suggestions":
            print("Use 'analyze' with sanitized observations to queue evidence-matched suggestions.")
            print("Next:",core.next_test(args.program))
        elif c=="next":
            row=core.next_test(args.program)
            print("Next plan (NOT executed):",row if row else "None")
        elif c=="approve": print(core.approve(args.program))
        elif c=="complete": print(core.complete(args.program,args.outcome))
        elif c in ("pause","resume"):
            with core.db(args.program) as conn:
                core.setmeta(conn,"paused","1" if c=="pause" else "0")
            print("Paused" if c=="pause" else "Resumed")
        elif c=="status":
            with core.db(args.program) as conn:
                print("Paused:",core.getmeta(conn,"paused","0")=="1")
                print("Recon complete:",core.getmeta(conn,"recon_done","0")=="1")
                print("Hosts:",conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0])
                print("Suggestions:",conn.execute("SELECT status,COUNT(*) FROM suggestions GROUP BY status").fetchall())
        elif c=="report": print("Report:",core.report(args.program))
        return 0
    except (ValueError,PermissionError,RuntimeError,OSError,KeyboardInterrupt) as e:
        print("BLOCKED/ERROR:",str(e))
        return 2
if __name__=="__main__":
    raise SystemExit(main())
