from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from .io import iter_artifact_files, load_artifacts, unpack_if_zip
from .report import build_report
from .rules import run_all_rules


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Разобрать аргументы командной строки для анализатора FastIR."""
    parser = argparse.ArgumentParser(description="Analyze FastIR collection output")
    parser.add_argument("input", type=Path, help="Path to FastIR output directory or ZIP archive")
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Report format")
    parser.add_argument("--output", type=Path, help="Path to write the report; defaults to stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Запустить полный цикл анализа вывода FastIR."""
    args = parse_args(argv)

    # Держим временную папку открытой до построения отчёта.
    with tempfile.TemporaryDirectory() as temp_dir:
        unpacked = unpack_if_zip(args.input, Path(temp_dir))
        paths = list(iter_artifact_files(unpacked))
        artifacts = load_artifacts(paths)
        findings = run_all_rules(artifacts)
        report = build_report(str(args.input), artifacts, findings)

        content = report.to_json() if args.format == "json" else report.to_text()

    if args.output:
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
