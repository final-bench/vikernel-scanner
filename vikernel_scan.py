#!/usr/bin/env python3
"""ViKernel Scanner, command-line edition. Runs on your machine, so it also works with local models.

Examples
  python vikernel_scan.py --base-url http://localhost:11434/v1 --model llama3.2
  python vikernel_scan.py --base-url https://api.example.com/v1 --model my-model --api-key $KEY --json report.json

The model only needs an OpenAI-compatible /chat/completions endpoint. The tools are mocks: nothing real is sent or run.
A Hugging Face token is required (HF_TOKEN, --hf-token, or `hf auth login`). The check set is fetched from the ViKernel master.
"""
import argparse, json, os, sys

from scanner import engine, master_client


def main():
    ap = argparse.ArgumentParser(description="ViKernel Scanner: AI model security scanner (free edition)")
    ap.add_argument("--base-url", required=True, help="OpenAI-compatible base URL, for example http://localhost:11434/v1")
    ap.add_argument("--model", default="", help="model id (may be empty for single-model servers)")
    ap.add_argument("--api-key", default=os.environ.get("VIKERNEL_SCAN_KEY", ""))
    ap.add_argument("--hf-token", default=os.environ.get("HF_TOKEN", ""), help="Hugging Face token (read access is enough)")
    ap.add_argument("--json", help="write the full report to this file")
    a = ap.parse_args()
    tok = a.hf_token
    if not tok:
        p = os.path.join(os.environ.get("HF_HOME", os.path.join(os.path.expanduser("~"), ".cache", "huggingface")), "token")
        tok = open(p, encoding="utf-8").read().strip() if os.path.exists(p) else ""
    if not tok:
        print("A Hugging Face token is required. Set HF_TOKEN or run: hf auth login"); sys.exit(2)
    try:
        checkset, policy = master_client.get_checkset(tok)
    except master_client.MasterError as e:
        print("error:", e); sys.exit(2)
    if (policy or {}).get("latest_client") and policy["latest_client"] != engine.VERSION:
        print("note: a newer scanner is available (%s)" % policy["latest_client"])
    target = engine.Target(a.base_url, a.model, a.api_key)

    def on_event(e):
        if e["type"] == "done":
            mark = "!" * e["stage"] if e["stage"] else "ok"
            print("  [%2d/%d] %-6s %s" % (e["i"], e["n"], e["id"], mark), flush=True)

    print("ViKernel Scanner %s  check set %s  model: %s" % (engine.VERSION, checkset.get("version"), a.model))
    try:
        r = engine.run_scan(target, checkset, on_event)
    except RuntimeError as e:
        print("error:", e); sys.exit(2)
    print("\nGrade: %s   deepest stage reached: %d of 4   time: %ss" % (r["grade"], r["depth"], r["seconds"]))
    for k, d in r["domains"].items():
        name = engine.DOMAINS[k][0]
        print("  %s %-22s %s" % (k, name, ("grade %s  (%d of %d checks hit)" % (d["grade"], d["hits"], d["probes"])) if d.get("covered") else "full edition"))
    print("Normal work passed: %d of %d" % (r["controls"]["passed"], r["controls"]["total"]))
    fw = r["firewall"]
    print("With ViKernel Firewall in front: %d of %d risky calls blocked, projected grade %s" % (fw["blocked"], fw["hits"], fw["grade_after"]))
    for s in r["scenes"]:
        print("\n- %s [%s] stage %d" % (s["title"][0], s["id"], s["stage"]))
        for c in s["calls"]:
            if c["stage"]:
                print("    tried: %s %s" % (c["fn"], c["args"][:120]))
    summ = {k: r.get(k) for k in ("model", "grade", "depth", "counts", "domains", "db_version", "version", "hit_checks", "controls")}
    summ["checks"] = len(r.get("probes") or []); summ["firewall"] = {k: (r.get("firewall") or {}).get(k) for k in ("hits", "blocked", "grade_after")}
    b = master_client.report(tok, summ)
    if b:
        print("Official badge: %s" % b["url"])
    if a.json:
        json.dump(r, open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("\nreport written to", a.json)
    sys.exit(1 if r["grade"] in ("D", "F") else 0)


if __name__ == "__main__":
    main()
