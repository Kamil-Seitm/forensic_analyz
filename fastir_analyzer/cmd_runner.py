from __future__ import annotations

import argparse
from pathlib import Path

from fastir_analyzer.orchestrator import collect_and_analyze


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Аргументы для автоматического запуска FastIR в консоли."""
    parser = argparse.ArgumentParser(description="Run FastIR, collect artifacts, and analyze them")
    parser.add_argument("fastir", type=Path, help="Путь до FastIR_x64.exe")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd() / "fastir_runs",
        help="Папка для выгрузки артефактов и отчёта (например C:/Temp/fastir_runs)",
    )
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Формат итогового отчёта")
    parser.add_argument(
        "--fastir-args",
        nargs=argparse.REMAINDER,
        help="Дополнительные аргументы для FastIR (передаются как есть после `--fastir-args`)",
    )
    parser.add_argument("--zip", dest="zip_results", action="store_true", help="Упаковать сырые данные и отчёт в ZIP")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.workspace.mkdir(parents=True, exist_ok=True)

    results = collect_and_analyze(
        args.fastir,
        args.workspace,
        report_format=args.format,
        extra_args=args.fastir_args,
        zip_results=args.zip_results,
    )

    print(f"FastIR raw artifacts: {results['raw']}")
    print(f"Report: {results['report']}")
    if "bundle" in results:
        print(f"Bundle: {results['bundle']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
