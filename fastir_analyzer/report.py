from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List

from .io import JsonLike


@dataclass
class Report:
    metadata: Dict[str, str]
    artifacts: Dict[str, List[JsonLike]]
    findings: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Преобразовать отчёт в словарь для сериализации."""
        return {
            "metadata": self.metadata,
            "artifact_counts": {k: len(v) for k, v in self.artifacts.items()},
            "findings": self.findings,
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Представить отчёт в виде JSON-строки."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_text(self) -> str:
        """Сформировать человекочитаемый текстовый отчёт."""
        lines = [
            f"Report generated at: {self.metadata.get('generated_at')}",
            f"Source: {self.metadata.get('source')}",
        ]

        verdict = self.metadata.get("verdict")
        score = self.metadata.get("score")
        verdict_text = self.metadata.get("verdict_text")

        if verdict:
            lines.append(f"Verdict: {verdict} (score={score})")
        if verdict_text:
            lines.append(f"Verdict details: {verdict_text}")

        lines.append("Artifacts:")
        for name, items in sorted(self.artifacts.items()):
            lines.append(f"  - {name}: {len(items)} records")

        lines.append("Findings:")
        if not self.findings:
            lines.append("  None")
        else:
            for finding in self.findings:
                details = ", ".join(
                    f"{k}={v}" for k, v in finding.items() if k not in {"category", "reason"}
                )
                lines.append(f"  - [{finding.get('category')}] {finding.get('reason')} ({details})")

        return "
".join(lines)


def classify_risk(findings: List[Dict[str, str]]) -> Dict[str, object]:
    """Очень простой скоринг: даёт итоговый вердикт по списку находок."""
    score = 0
    reasons: List[str] = []

    for f in findings:
        cat = (f.get("category") or "").lower()
        reason = f.get("reason") or ""
        vt = (f.get("virustotal") or f.get("vt_status") or "").lower()

        if "flagged" in vt:
            score += 5
            reasons.append(f"{cat}: VirusTotal flagged object ({reason})")
        elif cat in {"process", "network"}:
            score += 4
            reasons.append(f"{cat}: {reason}")
        elif cat in {"autorun", "service"}:
            score += 2
            reasons.append(f"{cat}: {reason}")
        else:
            score += 1
            reasons.append(f"{cat}: {reason}")

    if score >= 8:
        verdict = "compromised"
        verdict_text = "Высокая вероятность компрометации / бекдора"
    elif score >= 3:
        verdict = "suspicious"
        verdict_text = "Есть подозрительные артефакты, требуется более тщательный анализ"
    else:
        verdict = "clean"
        verdict_text = "Явных признаков заражения по текущим эвристикам не обнаружено"

    return {
        "verdict": verdict,
        "verdict_text": verdict_text,
        "score": score,
        "top_reasons": reasons[:5],
    }


def build_report(source: str, artifacts: Dict[str, List[JsonLike]], findings: List[Dict[str, str]]) -> Report:
    """Сконструировать объект отчёта с таймштампом и итоговым вердиктом."""
    summary = classify_risk(findings)
    metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": source,
        "verdict": summary["verdict"],
        "verdict_text": summary["verdict_text"],
        "score": str(summary["score"]),
    }
    return Report(metadata=metadata, artifacts=artifacts, findings=findings)
