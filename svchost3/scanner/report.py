from collections import Counter
from datetime import datetime
from pathlib import Path

from .system import write_json_file


def build_report(results, output_path):
    findings = sorted(
        results["findings"],
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "info": 3}.get(item["level"], 9),
            {"confirmed": 0, "probable": 1, "weak": 2}.get(item.get("confidence", "probable"), 9),
        ),
    )
    counts = Counter(item["level"] for item in findings)
    lines = []
    lines.append("WINDOWS SERVER 2019 LOCAL USER AUDIT")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"User: {results['identity']['domain']}\\{results['identity']['user']}".strip("\\"))
    lines.append(f"Risk score: {results['score']}/100")
    lines.append(f"Severity: {results['severity'].upper()}")
    lines.append(
        "Findings: "
        f"critical={counts.get('critical', 0)}, "
        f"high={counts.get('high', 0)}, "
        f"medium={counts.get('medium', 0)}, "
        f"info={counts.get('info', 0)}"
    )
    lines.append("")
    lines.append("CONFIRMED PATHS FIRST")
    lines.append("")
    confirmed = [item for item in findings if item.get("confidence") == "confirmed"]
    if not confirmed:
        lines.append("- No confirmed paths.")
    for item in confirmed[:15]:
        path_text = f" | path={item['path']}" if item.get("path") else ""
        lines.append(f"- [{item['level'].upper()}] {item['title']} | risk={item['risk']} | confidence={item['confidence']}{path_text}")
        lines.append(f"  evidence: {item['evidence']}")
    lines.append("")

    lines.append("TOP FINDINGS")
    lines.append("")
    if not findings:
        lines.append("- No findings were produced.")
    for index, item in enumerate(findings[:20], start=1):
        lines.append(f"{index}. [{item['level'].upper()}] {item['title']}")
        lines.append(f"   Check: {item['check']}")
        lines.append(f"   Risk: {item['risk']}")
        lines.append(f"   Confidence: {item.get('confidence', 'probable')}")
        if item.get("path"):
            lines.append(f"   Path: {item['path']}")
        lines.append(f"   Evidence: {item['evidence']}")
        lines.append("")

    lines.append("ALL FINDINGS")
    lines.append("")
    for item in findings:
        path_text = f" | path={item['path']}" if item.get("path") else ""
        lines.append(f"- [{item['level'].upper()}] {item['title']} | risk={item['risk']}{path_text}")
        lines.append(f"  evidence: {item['evidence']}")
    lines.append("")

    lines.append("CHECK COVERAGE")
    lines.append("")
    for name, meta in results.get("meta", {}).items():
        lines.append(f"- {name}: {meta}")
    lines.append("")
    lines.append("ADMIN-LEVEL ESCALATION ASSESSMENT")
    lines.append("")
    assessment = results.get("escalation_assessment", {})
    lines.append(f"- possible: {assessment.get('possible')}")
    lines.append(f"- confidence: {assessment.get('confidence')}")
    lines.append(f"- summary: {assessment.get('summary')}")
    classes = assessment.get("classes", [])
    if classes:
        lines.append(f"- exposure classes: {', '.join(classes)}")

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    json_path = str(Path(output_path).with_suffix(".json"))
    write_json_file(json_path, results)
