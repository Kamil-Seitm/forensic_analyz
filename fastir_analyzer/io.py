from __future__ import annotations

import csv
# Поднимаем лимит размера одного поля CSV (по умолчанию 128 КБ)
csv.field_size_limit(10 * 1024 * 1024)  # 10 МБ, можно больше, если захочешь
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Union

JsonLike = Dict[str, Any]


def _read_csv(path: Path) -> List[JsonLike]:
    """Прочитать CSV-файл FastIR и вернуть список словарей."""
    with path.open(newline="", encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        return [dict(row) for row in reader]


def _read_json(path: Path) -> Union[JsonLike, List[JsonLike]]:
    """Прочитать JSON-файл FastIR и вернуть словарь или список словарей."""
    with path.open(encoding="utf-8", errors="ignore") as fh:
        return json.load(fh)


def iter_artifact_files(base_path: Path) -> Iterable[Path]:
    """Итерироваться по всем файлам в папке артефактов или вернуть один файл."""
    if base_path.is_file():
        yield base_path
        return

    for path in base_path.rglob("*"):
        if path.is_file():
            yield path


def unpack_if_zip(path: Path, temp_dir: Path) -> Path:
    """Распаковать архив FastIR во временную папку, если это ZIP."""
    if path.suffix.lower() != ".zip":
        return path

    extract_dir = temp_dir / path.stem
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(extract_dir)
    return extract_dir


def load_artifacts(paths: Iterable[Path]) -> Dict[str, List[JsonLike]]:
    """Загрузить поддерживаемые артефакты в словарь вида <имя файла>: [записи]."""
    data: Dict[str, List[JsonLike]] = {}
    for path in paths:
        key = path.stem.lower()
        if path.suffix.lower() == ".csv":
            rows = _read_csv(path)
        elif path.suffix.lower() in {".json", ".js"}:
            loaded = _read_json(path)
            rows = loaded if isinstance(loaded, list) else [loaded]
        else:
            continue
        if not rows:
            continue
        data.setdefault(key, []).extend(rows)
    return data
