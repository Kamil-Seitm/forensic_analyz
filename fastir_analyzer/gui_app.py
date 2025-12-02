from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from .orchestrator import collect_and_analyze


class FastIRGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FastIR grab & analyze")
        self.fastir_path = tk.StringVar()
        self.workspace_path = tk.StringVar(value=str(Path.cwd() / "fastir_usb"))
        self.report_format = tk.StringVar(value="text")
        self.zip_results = tk.BooleanVar(value=True)

        self._build_layout()

    def _build_layout(self) -> None:
        tk.Label(self.root, text="FastIR_x64.exe:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        tk.Entry(self.root, textvariable=self.fastir_path, width=50).grid(row=0, column=1, padx=4, pady=4)
        tk.Button(self.root, text="Обзор", command=self._choose_fastir).grid(row=0, column=2, padx=4, pady=4)

        tk.Label(self.root, text="Корень флешки/папка вывода:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        tk.Entry(self.root, textvariable=self.workspace_path, width=50).grid(row=1, column=1, padx=4, pady=4)
        tk.Button(self.root, text="Обзор", command=self._choose_workspace).grid(row=1, column=2, padx=4, pady=4)

        tk.Label(self.root, text="Формат отчёта:").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        tk.OptionMenu(self.root, self.report_format, "text", "json").grid(row=2, column=1, sticky="w", padx=4, pady=4)

        tk.Checkbutton(self.root, text="Запаковать в ZIP", variable=self.zip_results).grid(
            row=3, column=1, sticky="w", padx=4, pady=4
        )

        tk.Button(self.root, text="Старт", command=self._start).grid(row=4, column=1, pady=10)
        self.status = tk.Label(self.root, text="Готово")
        self.status.grid(row=5, column=0, columnspan=3, sticky="w", padx=4, pady=4)

    def _choose_fastir(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите FastIR_x64.exe",
            filetypes=[("FastIR", "*.exe"), ("Любой", "*.*")],
        )
        if path:
            self.fastir_path.set(path)

    def _choose_workspace(self) -> None:
        path = filedialog.askdirectory(title="Куда писать результаты")
        if path:
            self.workspace_path.set(path)

    def _start(self) -> None:
        fastir = Path(self.fastir_path.get())
        workspace = Path(self.workspace_path.get())
        if not fastir.exists():
            messagebox.showerror("Ошибка", "Укажите существующий FastIR_x64.exe")
            return
        workspace.mkdir(parents=True, exist_ok=True)
        self.status.config(text="Запускаю FastIR и анализ...")
        thread = threading.Thread(target=self._run_pipeline, args=(fastir, workspace), daemon=True)
        thread.start()

    def _run_pipeline(self, fastir: Path, workspace: Path) -> None:
        try:
            results = collect_and_analyze(
                fastir,
                workspace,
                report_format=self.report_format.get(),
                extra_args=None,
                zip_results=self.zip_results.get(),
            )
        except Exception as exc:  # noqa: BLE001
            self._update_status(f"Ошибка: {exc}")
            return

        msg = (
            f"Готово! Сырые данные: {results['raw']}\n"
            f"Отчёт: {results['report']}"
        )
        if "bundle" in results:
            msg += f"\nZIP: {results['bundle']}"
        self._update_status(msg)
        messagebox.showinfo("Готово", msg)

    def _update_status(self, text: str) -> None:
        def _set() -> None:
            self.status.config(text=text)

        self.root.after(0, _set)


def main(argv: list[str] | None = None) -> int:  # noqa: ARG001
    root = tk.Tk()
    FastIRGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
