# cmd_fast_analyzed

Консольный сценарий для удалённого запуска через PsExec: собрать артефакты FastIR в `C:\Temp`, сразу получить отчёт.

## Сборка консольного варианта в `.exe` (на машине разработчика под Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install .
pip install pyinstaller
pyinstaller fastir_cmd.spec
```

Готовый `dist\fastir_cmd.exe` и `FastIR_x64.exe` копируем на целевой хост.

## Базовый запуск через PsExec

```bash
psexec \\TARGET -s -d C:\Temp\fastir_cmd.exe "C:\Temp\FastIR_x64.exe" --workspace C:\Temp\fastir_runs --zip
```

- Первый аргумент — путь к FastIR на целевой машине.
- `--workspace` — куда писать сырые CSV/JSON и отчёт.
- `--zip` — дополнительно упаковать результаты в ZIP.
- Дополнительные параметры FastIR можно передать после `--fastir-args`, например:
  ```bash
  fastir_cmd.exe "C:\Temp\FastIR_x64.exe" --workspace C:\Temp\fastir_runs --fastir-args -full -log --zip
  ```

## Что делает утилита

1. Создаёт папку `fastir_runs/fastir_YYYYMMDD_HHMMSS/fastir_raw` (или указанную вами).
2. Запускает `FastIR_x64.exe -o <raw_dir>` с переданными аргументами.
3. Анализирует выгруженные CSV/JSON, формирует `fastir_report.txt` (или `.json`).
4. При `--zip` кладёт `fastir_bundle.zip` рядом, удобно вытягивать одной командой `copy`/`robocopy`.

## Быстрая эвакуация результатов

После выполнения забираем всю папку `fastir_runs` или только ZIP:

```bash
copy \\TARGET\C$\Temp\fastir_runs\fastir_*.zip \\fileserver\cases\
```
