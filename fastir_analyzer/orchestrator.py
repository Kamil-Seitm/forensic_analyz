from __future__ import annotations

import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Sequence

from .io import iter_artifact_files, load_artifacts, unpack_if_zip
from .report import build_report
from .rules import run_all_rules


def run_fastir(fastir_path: Path, output_dir: Path, extra_args: Sequence[str] | None = None) -> Path:
    """Запустить FastIR и сохранить сырые артефакты в указанную папку."""
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd: List[str] = [str(fastir_path), "-o", str(output_dir)]
    if extra_args:
        cmd.extend(extra_args)
    subprocess.run(cmd, check=True)
    return output_dir


def analyze_collection(source: Path, report_format: str = "text") -> Dict[str, Path]:
    """Проанализировать папку или ZIP FastIR и записать отчёт рядом с исходными данными."""
    if source.is_file() and source.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory() as temp_dir:
            base = unpack_if_zip(source, Path(temp_dir))
            artifacts_paths = list(iter_artifact_files(base))
            artifacts = load_artifacts(artifacts_paths)
    else:
        base = source
        artifacts_paths = list(iter_artifact_files(base))
        artifacts = load_artifacts(artifacts_paths)

    findings = run_all_rules(artifacts)
    report = build_report(str(source), artifacts, findings)

    report_name = "fastir_report.json" if report_format == "json" else "fastir_report.txt"
    if source.is_dir():
        report_path = source / report_name
    else:
        report_path = source.with_suffix("." + report_name.split(".")[-1])

    content = report.to_json() if report_format == "json" else report.to_text()
    report_path.write_text(content, encoding="utf-8")
    return {"report": report_path}


def collect_and_analyze(
    fastir_path: Path,
    workspace: Path,
    *,
    report_format: str = "text",
    extra_args: Sequence[str] | None = None,
    zip_results: bool = False,
) -> Dict[str, Path]:
    """Собрать артефакты FastIR и сразу выпустить отчёт."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    collection_dir = workspace / f"fastir_{timestamp}"
    raw_dir = collection_dir / "fastir_raw"

    run_fastir(fastir_path, raw_dir, extra_args)
    results = analyze_collection(raw_dir, report_format=report_format)

    bundle_path = collection_dir / "fastir_bundle.zip"
    if zip_results:
        with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in raw_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, file_path.relative_to(collection_dir))
            zf.write(results["report"], results["report"].relative_to(collection_dir))
        results["bundle"] = bundle_path

    return {"workspace": collection_dir, "raw": raw_dir, **results}
