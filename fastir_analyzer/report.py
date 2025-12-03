from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Sequence


@dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    details: Dict[str, Any]


@dataclass
class Report:
    source: str
    created_at_utc: str
    artifacts_count: int
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "created_at_utc": self.created_at_utc,
            "artifacts_count": self.artifacts_count,
            "findings": [asdict(f) for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_text(self) -> str:
        lines: List[str] = []
        lines.append(f"FastIR report for: {self.source}")
        lines.append(f"Created at (UTC): {self.created_at_utc}")
        lines.append(f"Artifacts total: {self.artifacts_count}")
        lines.append("")

        if not self.findings:
            lines.append("Findings: none")
        else:
            lines.append("Findings:")
            for f in self.findings:
                lines.append("-" * 60)
                lines.append(f"[{f.severity}] {f.rule_id}: {f.description}")
                for k, v in f.details.items():
                    lines.append(f"  {k}: {v}")
        lines.append("")
        return "\n".join(lines)


def build_report(
    source: str,
    artifacts: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> Report:
    """Построить объект отчёта из артефактов и срабатываний правил."""

    parsed_findings: List[Finding] = []
    for item in findings:
        # ожидаем словарь, но на всякий пожарный используем get(...)
        rule_id = str(item.get("id", ""))
        severity = str(item.get("severity", "info"))
        description = str(item.get("description", ""))
        details_raw = item.get("details", {})

        if not isinstance(details_raw, dict):
            details: Dict[str, Any] = {"value": details_raw}
        else:
            details = details_raw

        parsed_findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                description=description,
                details=details,
            )
        )

    # грубый подсчёт количества артефактов
    artifacts_count = 0
    for value in artifacts.values():
        if isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict)):
            artifacts_count += len(list(value))
        else:
            artifacts_count += 1

    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    return Report(
        source=source,
        created_at_utc=created_at,
        artifacts_count=artifacts_count,
        findings=parsed_findings,
    )
