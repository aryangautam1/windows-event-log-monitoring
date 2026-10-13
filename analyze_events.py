import argparse, csv
from collections import Counter, defaultdict
from pathlib import Path

EVENTS = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4720": "User account created",
    "4740": "User account locked out",
    "4728": "Member added to security-enabled global group",
    "4732": "Member added to security-enabled local group",
}
def main():
    ap=argparse.ArgumentParser(description="Triage exported Windows Security events (CSV).")
    ap.add_argument("csv_file")
    ap.add_argument("--out", default="triage_report.md")
    ap.add_argument("--threshold", type=int, default=3, help="Failed logons per account/IP before flagging")
    args=ap.parse_args()
    with open(args.csv_file, newline="", encoding="utf-8-sig") as f:
        rows=list(csv.DictReader(f))
    failed=Counter()
    sources=defaultdict(set)
    counts=Counter()
    notable=[]
    for r in rows:
        eid=r.get("event_id","").strip()
        counts[eid]+=1
        if eid=="4625":
            key=(r.get("account","unknown"), r.get("source_ip","unknown"))
            failed[key]+=1
            sources[key[0]].add(key[1])
        if eid in {"4720","4728","4732","4740"}:
            notable.append(r)
    lines=["# Windows Security Event Triage Report","",f"- Events reviewed: **{len(rows)}**","", "## Event counts",""]
    for eid,n in sorted(counts.items()):
        lines.append(f"- Event ID {eid} ({EVENTS.get(eid,'Unmapped event')}): {n}")
    lines += ["","## Potential repeated failed logons",""]
    flagged=False
    for (account,ip),n in sorted(failed.items(), key=lambda x:x[1], reverse=True):
        if n>=args.threshold:
            flagged=True
            lines.append(f"- **Review:** account `{account}`, source `{ip}`, failed logons: **{n}**")
    if not flagged: lines.append("- No account/IP pair met the configured threshold.")
    lines += ["","## Account-management / lockout events",""]
    if notable:
        for r in notable:
            lines.append(f"- `{r.get('timestamp','')}` — Event {r.get('event_id')} ({EVENTS.get(r.get('event_id',''),'Review event')}); account `{r.get('account','unknown')}`; host `{r.get('computer','unknown')}`.")
    else: lines.append("- None in this dataset.")
    lines += ["","## Analyst notes","", "- Correlate source IP, logon type, host context, and surrounding events before declaring malicious activity.",
              "- A successful logon following failures is a lead to investigate, not proof of compromise.",
              "- Sample data is synthetic; validate findings against your lab before using as a portfolio case study.",""]
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True); out.write_text("\\n".join(lines),encoding="utf-8")
    print(f"Reviewed {len(rows)} events. Report written to {out}")
if __name__=="__main__": main()
