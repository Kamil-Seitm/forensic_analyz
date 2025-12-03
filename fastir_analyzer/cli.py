from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from fastir_analyzer.orchestrator import analyze_collection


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze FastIR collection output")
    parser.add_argument("input", type=Path, help="Path to FastIR output directory or ZIP archive")
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Report format (text or json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Куда сохранить отчёт (по умолчанию stdout)",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    results = analyze_collection(args.input, report_format=args.format)
    report_path = results["report"]
    content = report_path.read_text(encoding="utf-8")

    if args.output:
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
