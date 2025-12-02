# forensic_analyz
Forensic analyzer

Простой анализатор вывода FastIR. Умеет распаковывать архивы, читать CSV/JSON артефакты, применять несколько эвристических правил и выдавать текстовый или JSON отчёт.

## Установка

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -e .
```

## Использование

```bash
python -m fastir_analyzer <путь_к_папке_или_zip> --format json --output report.json
```

### Что делает анализатор

- Распаковывает архив `.zip`, если на вход подан архив FastIR.
- Рекурсивно собирает все файлы артефактов (CSV и JSON/JS) и нормализует их в словари Python.
- Запускает набор правил:
  - **autoruns** — ищет автозапуски, указывающие в `%TEMP%`, `\\Users\\Public` и т.п.
  - **services** — отмечает сервисы, которые стартуют бинарники из временных каталогов.
  - **network** — выводит соединения на внешние IP (не private/loopback) и дополнительно:
    - делает WHOIS-запрос по удалённому адресу/домену и отмечает VDS/VPS/hosting-сигнатуры в выводе;
    - при наличии `VT_API_KEY` проверяет адрес/домен в VirusTotal.
  - **processes** — подсвечивает PowerShell с аргументами, содержащими HTTP/HTTPS.
- Формирует отчёт с метаданными (источник, время генерации), количеством записей по каждому артефакту, списком срабатываний и итоговым вердиктом:
  - `clean` — явных признаков нет;
  - `suspicious` — есть подозрительные артефакты, надо копать;
  - `compromised` — высокая вероятность компрометации/бекдора.

### Быстрый запуск

- Текстовый отчёт:
  ```bash
  python -m fastir_analyzer C:\Temp\FastIR_Output
  ```

- JSON-отчёт в файл:
  ```bash
  python -m fastir_analyzer collection.zip --format json --output report.json
  ```

### Интеграция с VirusTotal

- Получите API-ключ и выставьте переменную окружения:

  ```bash
  set VT_API_KEY=ВАШ_КЛЮЧ  # Windows
  export VT_API_KEY=ВАШ_КЛЮЧ  # Linux/macOS
  ```

- Если ключ не задан, в поле `virustotal` будет пометка `VT API key missing`, но остальная логика (WHOIS, эвристики) продолжит работать.

### Готовые .exe (GUI и cmd)

Репозиторий содержит PyInstaller-спеки:

- `fastir_gui.spec` — сборка GUI под флешку;
- `fastir_cmd.spec` — консольный вариант под PsExec.

Подробнее см. файлы:

- `GUI_flesh_Fast_IR_analyz.md`
- `cmd_fast_analyzed.md`
