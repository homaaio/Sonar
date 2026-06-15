#!/usr/bin/env python3
"""
Sonar — Диагностика файлов и устройств
Версия 3.0 с C-ядром, безопасностью и логированием
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, queue, os, sys, zipfile, tarfile
import gzip, bz2, lzma, zlib, struct, time, wave
import subprocess, platform, json, ctypes, tempfile, logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sonar.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
#  C-ЯДРО  (sonar_core.so / sonar_core.dll)
# ══════════════════════════════════════════════════════════════════════════════

def _find_lib():
    """Ищет скомпилированную библиотеку рядом со скриптом или в temp."""
    script_dir = Path(__file__).parent
    candidates = [
        script_dir / "sonar_core.so",
        script_dir / "sonar_core.dll",
        Path(tempfile.gettempdir()) / "sonar_core.so",
        Path(tempfile.gettempdir()) / "sonar_core.dll",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None

def _compile_lib(dst: str) -> bool:
    """Компилирует C-ядро на лету, если gcc/clang доступен."""
    # ... (оставляем существующий код компиляции)
    src_path = Path(dst).with_suffix('.c')
    try:
        # Копируем полный C-код из sonar_core.c
        with open(src_path, "w") as f:
            f.write(open(__file__.replace('.py', '_core.c')).read())
        
        compiler = None
        for comp in ["gcc", "clang", "cc"]:
            if subprocess.run(["which", comp], capture_output=True).returncode == 0:
                compiler = comp
                break
        
        if not compiler:
            logger.warning("No C compiler found")
            return False
        
        ret = subprocess.run(
            [compiler, "-O2", "-shared", "-fPIC", "-o", dst, str(src_path), "-lm"],
            capture_output=True, timeout=30)
        if ret.returncode == 0:
            logger.info(f"C core compiled successfully: {dst}")
            return True
        else:
            logger.error(f"Compilation failed: {ret.stderr}")
            return False
    except Exception as e:
        logger.error(f"Compilation error: {e}")
        return False


class SonarCore:
    """Обёртка над C-библиотекой с полной поддержкой всех функций."""

    def __init__(self):
        self._lib = None
        self._available = False
        self._load_library()
        
    def _load_library(self):
        lib_path = _find_lib()
        if not lib_path:
            dst = str(Path(tempfile.gettempdir()) / ("sonar_core.so" if sys.platform != "win32" else "sonar_core.dll"))
            if _compile_lib(dst):
                lib_path = dst
        
        if lib_path:
            try:
                self._lib = ctypes.CDLL(lib_path)
                
                # Определяем типы аргументов для всех функций
                self._lib.set_language.argtypes = [ctypes.c_int]
                self._lib.get_language.restype = ctypes.c_int
                
                self._lib.scan_entropy.argtypes = [ctypes.c_char_p]
                self._lib.scan_entropy.restype = ctypes.c_double
                
                self._lib.scan_nullratio.argtypes = [ctypes.c_char_p]
                self._lib.scan_nullratio.restype = ctypes.c_double
                
                self._lib.scan_ascii_ratio.argtypes = [ctypes.c_char_p]
                self._lib.scan_ascii_ratio.restype = ctypes.c_double
                
                self._lib.calc_crc32.argtypes = [ctypes.c_char_p]
                self._lib.calc_crc32.restype = ctypes.c_uint32
                
                self._lib.scan_pattern.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
                self._lib.scan_pattern.restype = ctypes.c_int64
                
                self._lib.byte_histogram.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64)]
                
                self._lib.is_text_file.argtypes = [ctypes.c_char_p]
                self._lib.is_text_file.restype = ctypes.c_int
                
                self._lib.scan_security.argtypes = [ctypes.c_char_p]
                self._lib.scan_security.restype = ctypes.c_void_p
                
                self._lib.free_security_result.argtypes = [ctypes.c_void_p]
                self._lib.get_threat_level.argtypes = [ctypes.c_void_p]
                self._lib.get_threat_level.restype = ctypes.c_int
                self._lib.get_suspicious_count.argtypes = [ctypes.c_void_p]
                self._lib.get_suspicious_count.restype = ctypes.c_int
                
                self._lib.core_log_info.argtypes = [ctypes.c_char_p]
                self._lib.core_log_error.argtypes = [ctypes.c_char_p]
                self._lib.core_log_warning.argtypes = [ctypes.c_char_p]
                
                self._available = True
                logger.info("C core loaded successfully")
                self.core_log_info("Python interface initialized")
            except Exception as e:
                logger.error(f"Failed to load C core: {e}")
                self._available = False
    
    @property
    def available(self):
        return self._available
    
    def set_language(self, lang: int):
        if self._available:
            self._lib.set_language(lang)
            logger.info(f"Language set to {lang}")
    
    def get_language(self) -> int:
        if self._available:
            return self._lib.get_language()
        return 1  # EN по умолчанию
    
    def entropy(self, path: str) -> float:
        if self._available:
            return self._lib.scan_entropy(path.encode())
        return self._py_entropy(path)
    
    def null_ratio(self, path: str) -> float:
        if self._available:
            return self._lib.scan_nullratio(path.encode())
        return 0.0
    
    def ascii_ratio(self, path: str) -> float:
        if self._available:
            return self._lib.scan_ascii_ratio(path.encode())
        return 0.0
    
    def crc32(self, path: str) -> int:
        if self._available:
            return self._lib.calc_crc32(path.encode())
        return 0
    
    def histogram(self, path: str) -> List[int]:
        if self._available:
            arr = (ctypes.c_uint64 * 256)()
            self._lib.byte_histogram(path.encode(), arr)
            return list(arr)
        return [0]*256
    
    def is_text_file(self, path: str) -> bool:
        if self._available:
            return self._lib.is_text_file(path.encode()) == 1
        return False
    
    def scan_security(self, path: str) -> Optional[Dict]:
        """Сканирует файл на наличие вредоносных признаков."""
        if not self._available:
            return None
        
        result_ptr = self._lib.scan_security(path.encode())
        if not result_ptr:
            return None
        
        threat_level = self._lib.get_threat_level(result_ptr)
        reasons_count = self._lib.get_suspicious_count(result_ptr)
        
        reasons = []
        for i in range(reasons_count):
            # Получаем указатель на строку
            reason_func = getattr(self._lib, 'get_suspicious_reason')
            reason_func.argtypes = [ctypes.c_void_p, ctypes.c_int]
            reason_func.restype = ctypes.c_char_p
            reason = reason_func(result_ptr, i).decode()
            reasons.append(reason)
        
        self._lib.free_security_result(result_ptr)
        
        return {
            "threat_level": threat_level,
            "is_suspicious": threat_level >= 5,
            "reasons": reasons,
            "severity": "HIGH" if threat_level >= 7 else "MEDIUM" if threat_level >= 4 else "LOW"
        }
    
    def core_log_info(self, msg: str):
        if self._available:
            self._lib.core_log_info(msg.encode())
    
    def core_log_error(self, msg: str):
        if self._available:
            self._lib.core_log_error(msg.encode())
    
    def core_log_warning(self, msg: str):
        if self._available:
            self._lib.core_log_warning(msg.encode())
    
    def entropy_description(self, entropy: float) -> str:
        """Возвращает описание энтропии на текущем языке."""
        if self._available:
            desc_func = self._lib.entropy_description
            desc_func.argtypes = [ctypes.c_double]
            desc_func.restype = ctypes.c_char_p
            return desc_func(entropy).decode()
        return "Неизвестно"
    
    def get_message(self, msg_id: int) -> str:
        """Получает локализованное сообщение."""
        if self._available:
            msg_func = self._lib.get_message
            msg_func.argtypes = [ctypes.c_int]
            msg_func.restype = ctypes.c_char_p
            return msg_func(msg_id).decode()
        return "???"
    
    # Python fallback для энтропии
    def _py_entropy(self, path: str) -> float:
        try:
            import math
            freq = [0]*256
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    for b in chunk:
                        freq[b] += 1
            total = sum(freq)
            if total == 0:
                return 0.0
            e = 0.0
            for c in freq:
                if c:
                    p = c/total
                    e -= p * math.log2(p)
            return e
        except Exception:
            return 0.0


CORE = SonarCore()


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ ОКНО
# ══════════════════════════════════════════════════════════════════════════════

class SonarApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sonar — Диагностика файлов и устройств v3.0")
        self.geometry("1024x680")
        self.minsize(800, 600)
        
        # Инициализация
        self._q = queue.Queue()
        self._checker = FileChecker()
        self._running = False
        self._results = []
        self._file_paths = []
        self._kbd_active = False
        self._mouse_active = False
        self._current_lang = 1  # EN по умолчанию
        
        # Настройка C-ядра
        if CORE.available:
            CORE.set_language(self._current_lang)
            CORE.core_log_info("Sonar application started")
        
        self._build_ui()
        self._poll_queue()
        self._update_status("Готов к работе")
        logger.info("Application initialized")
    
    def _build_ui(self):
        # Windows-тема
        style = ttk.Style(self)
        for theme in ("vista", "winnative", "xpnative", "clam"):
            try:
                style.theme_use(theme)
                break
            except Exception:
                pass
        
        self._create_menu()
        self._create_toolbar()
        
        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        
        files_tab = ttk.Frame(nb)
        devices_tab = ttk.Frame(nb)
        nb.add(files_tab, text="   Файлы   ")
        nb.add(devices_tab, text="   Устройства   ")
        
        self._build_files_tab(files_tab)
        self._build_devices_tab(devices_tab)
        
        # Статус бар
        self._create_statusbar()
    
    def _create_menu(self):
        menubar = tk.Menu(self, tearoff=0)
        
        # Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Добавить файлы", accelerator="Ctrl+O", command=self._add_files)
        file_menu.add_command(label="Добавить папку", accelerator="Ctrl+D", command=self._add_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Сохранить отчёт", accelerator="Ctrl+S", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        # Сканирование
        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(label="Быстрое сканирование", accelerator="F5", command=self._start_scan)
        scan_menu.add_command(label="Детальный разбор", accelerator="F6", command=self._start_deep)
        scan_menu.add_command(label="Проверка безопасности", accelerator="F7", command=self._security_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Очистить список", command=self._clear)
        menubar.add_cascade(label="Сканирование", menu=scan_menu)
        
        # Язык
        lang_menu = tk.Menu(menubar, tearoff=0)
        lang_menu.add_command(label="Русский", command=lambda: self._set_language(0))
        lang_menu.add_command(label="English", command=lambda: self._set_language(1))
        lang_menu.add_command(label="Français", command=lambda: self._set_language(2))
        menubar.add_cascade(label="Язык", menu=lang_menu)
        
        # Справка
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self._about)
        menubar.add_cascade(label="Справка", menu=help_menu)
        
        self.config(menu=menubar)
        
        # Горячие клавиши
        self.bind("<Control-o>", lambda e: self._add_files())
        self.bind("<Control-d>", lambda e: self._add_folder())
        self.bind("<Control-s>", lambda e: self._export_report())
        self.bind("<F5>", lambda e: self._start_scan())
        self.bind("<F6>", lambda e: self._start_deep())
        self.bind("<F7>", lambda e: self._security_scan())
        self.bind("<Return>", lambda e: self._show_details())
    
    def _set_language(self, lang_code: int):
        """Установка языка интерфейса и C-ядра."""
        self._current_lang = lang_code
        if CORE.available:
            CORE.set_language(lang_code)
            CORE.core_log_info(f"Language changed to {lang_code}")
        
        lang_names = ["Русский", "English", "Français"]
        self._update_status(f"Язык переключён на: {lang_names[lang_code]}")
        
        # Обновляем отображение деталей если есть выбранный файл
        selection = self._tree.selection()
        if selection:
            path = selection[0]
            result = next((r for r in self._results if r["path"] == path), None)
            if result:
                self._render_details(result)
    
    def _create_toolbar(self):
        toolbar = tk.Frame(self, bg="#F0F0F0", relief="raised", bd=1, height=32)
        toolbar.pack(fill="x", side="top")
        toolbar.pack_propagate(False)
        
        buttons = [
            ("📄 Добавить файлы", self._add_files),
            ("📁 Добавить папку", self._add_folder),
            ("▶ Сканировать", self._start_scan),
            ("🔬 Детально", self._start_deep),
            ("🛡 Безопасность", self._security_scan),
            ("✕ Очистить", self._clear),
            ("💾 Отчёт", self._export_report),
        ]
        
        for text, cmd in buttons:
            btn = tk.Button(toolbar, text=text, command=cmd,
                          relief="flat", bg="#F0F0F0", font=("Segoe UI", 8),
                          cursor="hand2")
            btn.pack(side="left", padx=2, pady=2)
            btn.bind("<Enter>", lambda e, b=btn: b.config(relief="raised"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(relief="flat"))
        
        # C-ядро индикатор
        c_status = "✓ C-ядро активно" if CORE.available else "✗ C-ядро неактивно"
        c_color = "#006400" if CORE.available else "#8B0000"
        c_label = tk.Label(toolbar, text=c_status, bg="#F0F0F0", fg=c_color,
                          font=("Consolas", 8))
        c_label.pack(side="right", padx=10)
    
    def _create_statusbar(self):
        status_bar = tk.Frame(self, bg="#D4D0C8", relief="sunken", bd=1, height=24)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        
        self._status_left = tk.Label(status_bar, text="Готов", bg="#D4D0C8",
                                     font=("Segoe UI", 8), anchor="w")
        self._status_left.pack(side="left", fill="x", expand=True, padx=4)
        
        self._status_right = tk.Label(status_bar, text="", bg="#D4D0C8",
                                      font=("Segoe UI", 8), anchor="e")
        self._status_right.pack(side="right", padx=4)
        
        self._update_datetime()
    
    def _update_datetime(self):
        self._status_right.config(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._update_datetime)
    
    def _update_status(self, text: str):
        self._status_left.config(text=f"  {text}")
        logger.info(f"Status: {text}")
    
    def _build_files_tab(self, parent):
        # Создаём дерево файлов
        paned = tk.PanedWindow(parent, orient="horizontal", sashwidth=4)
        paned.pack(fill="both", expand=True)
        
        # Левая панель - список файлов
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, width=700)
        
        columns = ("status", "name", "type", "size", "security", "detail")
        self._tree = ttk.Treeview(left_frame, columns=columns, show="headings", selectmode="browse")
        
        self._tree.heading("status", text="")
        self._tree.heading("name", text="Имя файла", anchor="w")
        self._tree.heading("type", text="Тип", anchor="center")
        self._tree.heading("size", text="Размер", anchor="e")
        self._tree.heading("security", text="Безопасность", anchor="center")
        self._tree.heading("detail", text="Результат", anchor="w")
        
        self._tree.column("status", width=30, anchor="center")
        self._tree.column("name", width=250, minwidth=150)
        self._tree.column("type", width=100, anchor="center")
        self._tree.column("size", width=90, anchor="e")
        self._tree.column("security", width=100, anchor="center")
        self._tree.column("detail", width=300)
        
        # Скроллбары
        v_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self._tree.yview)
        h_scroll = ttk.Scrollbar(left_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self._tree.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")
        h_scroll.pack(side="bottom", fill="x")
        
        self._tree.tag_configure("safe", foreground="#006400")
        self._tree.tag_configure("suspicious", foreground="#8B0000")
        self._tree.tag_configure("unknown", foreground="#7A5500")
        self._tree.bind("<Double-1>", lambda e: self._show_details())
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        
        # Правая панель - детали
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, width=300)
        
        ttk.Label(right_frame, text="Детальная информация", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=5)
        ttk.Separator(right_frame, orient="horizontal").pack(fill="x", padx=5)
        
        self._detail_text = tk.Text(right_frame, font=("Consolas", 8), wrap="word",
                                    state="disabled", relief="flat", bg="#FAFAFA")
        self._detail_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Прогресс бар
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill="x", padx=5, pady=5)
        
        self._progress_bar = ttk.Progressbar(progress_frame, mode="determinate", length=200)
        self._progress_bar.pack(side="left", padx=5)
        
        self._progress_label = ttk.Label(progress_frame, text="Готов")
        self._progress_label.pack(side="left")
        
        self._progress_count = ttk.Label(progress_frame, text="")
        self._progress_count.pack(side="right")
    
    def _security_scan(self):
        """Запуск сканирования безопасности."""
        selection = self._tree.selection()
        if not selection:
            messagebox.showinfo("Sonar", "Выберите файл для проверки безопасности")
            return
        
        path = selection[0]
        self._update_status(f"Проверка безопасности: {os.path.basename(path)}")
        
        def worker():
            result = CORE.scan_security(path)
            self._q.put(("security_result", path, result))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_tree_select(self, event):
        selection = self._tree.selection()
        if not selection:
            return
        
        path = selection[0]
        result = next((r for r in self._results if r["path"] == path), None)
        if result:
            self._render_details(result)
    
    def _render_details(self, result: Dict):
        """Отображает детальную информацию о файле."""
        self._detail_text.config(state="normal")
        self._detail_text.delete("1.0", "end")
        
        # Заголовок с статусом
        status_icon = {"ok": "✓", "warn": "⚠", "error": "✗"}.get(result.get("status", "warn"), "?")
        status_text = {"ok": "ИСПРАВЕН", "warn": "ВНИМАНИЕ", "error": "ПОВРЕЖДЁН"}.get(result.get("status", "warn"), "НЕИЗВЕСТНО")
        
        self._detail_text.insert("end", f"{status_icon} {status_text}\n", "title")
        self._detail_text.insert("end", "─" * 40 + "\n", "separator")
        
        # Основная информация
        self._detail_text.insert("end", f"Имя: {result.get('name', '?')}\n", "field")
        self._detail_text.insert("end", f"Путь: {result.get('path', '?')}\n", "field")
        self._detail_text.insert("end", f"Тип: {result.get('type', '?')}\n", "field")
        self._detail_text.insert("end", f"Размер: {self._format_size(result.get('size', 0))}\n", "field")
        
        # Глубокий анализ
        deep = result.get("deep", {})
        if deep:
            self._detail_text.insert("end", "\n📊 Статистика:\n", "header")
            self._detail_text.insert("end", f"  Энтропия: {deep.get('entropy', 0):.4f} бит/байт\n", "field")
            self._detail_text.insert("end", f"  {deep.get('entropy_hint', '')}\n", "hint")
            self._detail_text.insert("end", f"  CRC-32: {deep.get('crc32', '?')}\n", "field")
            self._detail_text.insert("end", f"  Нулевые байты: {deep.get('null_ratio', 0):.2f}%\n", "field")
            self._detail_text.insert("end", f"  ASCII: {deep.get('ascii_ratio', 0):.2f}%\n", "field")
        
        # Безопасность
        security = result.get("security", {})
        if security:
            self._detail_text.insert("end", "\n🛡 Безопасность:\n", "header")
            threat_level = security.get("threat_level", 0)
            severity = security.get("severity", "UNKNOWN")
            
            severity_colors = {"LOW": "#006400", "MEDIUM": "#7A5500", "HIGH": "#8B0000"}
            self._detail_text.insert("end", f"  Уровень угрозы: {threat_level}/10 [{severity}]\n", 
                                    ("field", severity_colors.get(severity, "black")))
            
            if security.get("is_suspicious"):
                self._detail_text.insert("end", "  ⚠ ОБНАРУЖЕНЫ ПОДОЗРИТЕЛЬНЫЕ ПРИЗНАКИ:\n", "warning")
                for reason in security.get("reasons", []):
                    self._detail_text.insert("end", f"    • {reason}\n", "warning")
            else:
                self._detail_text.insert("end", "  ✓ Подозрительных признаков не обнаружено\n", "safe")
        
        # Проблемы
        issues = result.get("issues", [])
        if issues:
            self._detail_text.insert("end", "\n⚠ Проблемы:\n", "header")
            for issue in issues:
                self._detail_text.insert("end", f"  • {issue}\n", "warning")
        
        # Стили
        self._detail_text.tag_config("title", font=("Segoe UI", 10, "bold"))
        self._detail_text.tag_config("header", font=("Segoe UI", 9, "bold"))
        self._detail_text.tag_config("field", font=("Consolas", 8))
        self._detail_text.tag_config("hint", foreground="#666666", font=("Consolas", 7))
        self._detail_text.tag_config("warning", foreground="#8B0000", font=("Consolas", 8))
        self._detail_text.tag_config("safe", foreground="#006400")
        self._detail_text.tag_config("separator", foreground="#CCCCCC")
        
        self._detail_text.config(state="disabled")
    
    def _build_devices_tab(self, parent):
        # Аналогично существующему коду...
        pass
    
    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Выберите файлы")
        for path in paths:
            if path not in self._file_paths:
                self._file_paths.append(path)
                self._insert_pending(path)
        self._update_status(f"Добавлено {len(paths)} файлов")
    
    def _add_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку")
        if not folder:
            return
        
        count = 0
        for root, dirs, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)
                if path not in self._file_paths:
                    self._file_paths.append(path)
                    self._insert_pending(path)
                    count += 1
        self._update_status(f"Добавлено {count} файлов из папки")
    
    def _insert_pending(self, path: str):
        name = os.path.basename(path)
        size = self._format_size(os.path.getsize(path)) if os.path.exists(path) else "?"
        self._tree.insert("", "end", iid=path, values=("○", name, "?", size, "?", "ожидание..."),
                         tags=("unknown",))
    
    def _start_scan(self):
        if self._running:
            messagebox.showinfo("Sonar", "Сканирование уже выполняется")
            return
        
        if not self._file_paths:
            messagebox.showinfo("Sonar", "Нет файлов для сканирования")
            return
        
        self._running = True
        self._results = []
        self._progress_bar.configure(maximum=len(self._file_paths), value=0)
        self._progress_label.config(text="Сканирование...")
        
        threading.Thread(target=self._scan_worker, daemon=True).start()
    
    def _scan_worker(self):
        for i, path in enumerate(self._file_paths):
            result = self._checker.check(path)
            self._results.append(result)
            self._q.put(("scan_result", i + 1, len(self._file_paths), result))
            time.sleep(0.01)
        self._q.put(("scan_done", len(self._file_paths)))
    
    def _start_deep(self):
        selection = self._tree.selection()
        if not selection:
            if not self._file_paths:
                messagebox.showinfo("Sonar", "Нет файлов для анализа")
                return
            self._start_deep_all()
        else:
            self._start_deep_single(selection[0])
    
    def _start_deep_single(self, path: str):
        if self._running:
            messagebox.showinfo("Sonar", "Операция уже выполняется")
            return
        
        self._running = True
        self._progress_label.config(text="Глубокий анализ...")
        
        def worker():
            result = self._checker.deep_analyze(path)
            
            # Добавляем проверку безопасности
            security = CORE.scan_security(path)
            if security:
                result["security"] = security
            
            # Обновляем результат
            existing = next((r for r in self._results if r["path"] == path), None)
            if existing:
                existing.update(result)
            else:
                self._results.append(result)
            
            self._q.put(("deep_done", result, path))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _start_deep_all(self):
        if self._running:
            return
        
        self._running = True
        total = len(self._file_paths)
        self._progress_bar.configure(maximum=total * 10, value=0)
        
        def worker():
            for i, path in enumerate(self._file_paths):
                result = self._checker.deep_analyze(path)
                
                security = CORE.scan_security(path)
                if security:
                    result["security"] = security
                
                self._results.append(result)
                self._q.put(("scan_result", i + 1, total, result))
                self._q.put(("progress", (i + 1) * 10))
            self._q.put(("scan_done", total))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _clear(self):
        if self._running:
            messagebox.showinfo("Sonar", "Дождитесь завершения операции")
            return
        
        self._file_paths.clear()
        self._results.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        
        self._progress_bar.configure(value=0)
        self._progress_label.config(text="Готов")
        self._progress_count.config(text="")
        self._update_status("Список очищен")
    
    def _export_report(self):
        if not self._results:
            messagebox.showinfo("Sonar", "Нет данных для экспорта")
            return
        
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt"), ("JSON", "*.json")],
            initialfile=f"sonar_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if not path:
            return
        
        if path.endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                # Убираем гистограмму для экономии места
                safe_results = []
                for r in self._results:
                    r_copy = dict(r)
                    if "deep" in r_copy and "histogram" in r_copy["deep"]:
                        del r_copy["deep"]["histogram"]
                    safe_results.append(r_copy)
                json.dump(safe_results, f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(f"SONAR ОТЧЁТ\n")
                f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"C-ядро: {'Активно' if CORE.available else 'Неактивно'}\n")
                f.write("=" * 70 + "\n\n")
                
                for r in self._results:
                    status = r.get("status", "unknown")
                    status_text = {"ok": "ИСПРАВЕН", "warn": "ВНИМАНИЕ", "error": "ПОВРЕЖДЁН"}.get(status, "?")
                    
                    f.write(f"[{status_text}] {r.get('name', '?')}\n")
                    f.write(f"  Путь: {r.get('path', '?')}\n")
                    f.write(f"  Тип: {r.get('type', '?')}\n")
                    f.write(f"  Размер: {self._format_size(r.get('size', 0))}\n")
                    
                    deep = r.get("deep", {})
                    if deep:
                        f.write(f"  Энтропия: {deep.get('entropy', 0):.4f} бит/байт\n")
                        f.write(f"  CRC-32: {deep.get('crc32', '?')}\n")
                    
                    security = r.get("security", {})
                    if security:
                        f.write(f"  Уровень угрозы: {security.get('threat_level', 0)}/10\n")
                        if security.get("is_suspicious"):
                            f.write("  ПОДОЗРИТЕЛЬНЫЕ ПРИЗНАКИ:\n")
                            for reason in security.get("reasons", []):
                                f.write(f"    - {reason}\n")
                    
                    f.write("\n")
        
        messagebox.showinfo("Sonar", f"Отчёт сохранён:\n{path}")
        self._update_status(f"Отчёт экспортирован: {os.path.basename(path)}")
    
    def _show_details(self):
        selection = self._tree.selection()
        if not selection:
            return
        
        path = selection[0]
        result = next((r for r in self._results if r["path"] == path), None)
        if result:
            self._render_details(result)
        else:
            self._start_deep_single(path)
    
    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                
                if msg[0] == "scan_result":
                    _, current, total, result = msg
                    self._update_row(result)
                    self._progress_bar.configure(value=current)
                    self._progress_label.config(text=f"Сканирование: {current}/{total}")
                    self._progress_count.config(text=f"{current}/{total}")
                
                elif msg[0] == "scan_done":
                    total = msg[1]
                    self._running = False
                    ok = sum(1 for r in self._results if r.get("status") == "ok")
                    warn = sum(1 for r in self._results if r.get("status") == "warn")
                    err = sum(1 for r in self._results if r.get("status") == "error")
                    
                    self._progress_label.config(text="Сканирование завершено")
                    self._progress_count.config(text=f"✓ {ok}  ⚠ {warn}  ✗ {err}")
                    self._update_status(f"Сканирование завершено: OK={ok}, WARN={warn}, ERROR={err}")
                    logger.info(f"Scan completed: OK={ok}, WARN={warn}, ERROR={err}")
                
                elif msg[0] == "deep_done":
                    result, path = msg[1], msg[2]
                    self._update_row(result)
                    self._running = False
                    self._progress_label.config(text="Анализ завершён")
                    self._render_details(result)
                    self._update_status(f"Глубокий анализ завершён: {os.path.basename(path)}")
                
                elif msg[0] == "security_result":
                    path, security = msg[1], msg[2]
                    # Находим и обновляем результат
                    for result in self._results:
                        if result["path"] == path:
                            result["security"] = security
                            self._update_row(result)
                            self._render_details(result)
                            break
                    
                    if security:
                        level = security.get("threat_level", 0)
                        if level >= 7:
                            messagebox.showwarning("Sonar - Предупреждение безопасности",
                                f"Файл {os.path.basename(path)}\n"
                                f"Обнаружены признаки вредоносного ПО!\n"
                                f"Уровень угрозы: {level}/10\n\n"
                                f"Причины:\n" + "\n".join(security.get("reasons", [])))
                    
                    self._update_status(f"Проверка безопасности завершена")
                
                elif msg[0] == "progress":
                    value = msg[1]
                    self._progress_bar.configure(value=value)
        
        except queue.Empty:
            pass
        
        self.after(100, self._poll_queue)
    
    def _update_row(self, result: Dict):
        """Обновляет строку в дереве файлов."""
        status_icon = {"ok": "✓", "warn": "⚠", "error": "✗"}.get(result.get("status", "warn"), "?")
        
        security = result.get("security", {})
        if security:
            threat = security.get("threat_level", 0)
            if threat >= 7:
                security_text = "⚠ ОПАСНО"
                tag = "suspicious"
            elif threat >= 4:
                security_text = "⚠ ВНИМАНИЕ"
                tag = "suspicious"
            else:
                security_text = "✓ Безопасно"
                tag = "safe"
        else:
            security_text = "—"
            tag = "unknown"
        
        detail = result.get("details", ["—"])[0] if result.get("details") else "—"
        
        try:
            self._tree.item(result["path"],
                          values=(status_icon, result["name"], result["type"],
                                 self._format_size(result["size"]), security_text, detail),
                          tags=(tag,))
        except Exception:
            pass
    
    @staticmethod
    def _format_size(size: int) -> str:
        """Форматирует размер в человеко-читаемый вид."""
        for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
            if size < 1024:
                return f"{size:.1f} {unit}" if unit != "Б" else f"{size} {unit}"
            size /= 1024
        return f"{size:.1f} ПБ"
    
    def _about(self):
        """О программе с GitHub ссылкой и иконкой."""
        about_window = tk.Toplevel(self)
        about_window.title("О программе Sonar")
        about_window.geometry("500x450")
        about_window.resizable(False, False)
        
        # Центрируем окно
        about_window.transient(self)
        about_window.grab_set()
        
        # Основной фрейм
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill="both", expand=True)
        
        # Заголовок
        title_label = ttk.Label(main_frame, text="Sonar", font=("Segoe UI", 20, "bold"))
        title_label.pack()
        
        version_label = ttk.Label(main_frame, text="Версия 3.0", font=("Segoe UI", 10))
        version_label.pack()
        
        ttk.Label(main_frame, text="Диагностика файлов и устройств", font=("Segoe UI", 9)).pack(pady=(5, 15))
        
        # Описание
        desc_text = """Sonar - инструмент для глубокого анализа файлов и диагностики устройств.

Возможности:
• Быстрая проверка целостности файлов
• Детальный анализ (энтропия, CRC-32, статистика)
• Проверка безопасности и обнаружение вредоносных признаков
• Диагностика устройств ввода (клавиатура, мышь, микрофон)
• Многоязычный интерфейс (RU/EN/FR)
• Экспорт отчётов в TXT/JSON
• C-ядро для максимальной производительности
• Полное логирование всех операций

Технологии: Python 3, Tkinter, C (ctypes), многопоточность"""
        
        desc_widget = tk.Text(main_frame, wrap="word", height=14, width=55,
                               font=("Segoe UI", 8), relief="flat", bg="#F0F0F0")
        desc_widget.insert("1.0", desc_text)
        desc_widget.config(state="disabled")
        desc_widget.pack(pady=10)
        
        # GitHub ссылка
        github_frame = ttk.Frame(main_frame)
        github_frame.pack(pady=10)
        
        # Пробуем загрузить иконку GitHub
        icon_paths = [
            Path(__file__).parent / "Assets" / "github_icon.png",
            Path(__file__).parent.parent / "Assets" / "github_icon.png",
            Path("Assets") / "github_icon.png",
        ]
        
        github_icon = None
        for icon_path in icon_paths:
            if icon_path.exists():
                try:
                    github_img = tk.PhotoImage(file=str(icon_path))
                    # Уменьшаем иконку если нужно
                    github_icon = github_img.subsample(2, 2) if github_img.width() > 32 else github_img
                    break
                except Exception as e:
                    logger.warning(f"Cannot load GitHub icon: {e}")
        
        if github_icon:
            icon_label = ttk.Label(github_frame, image=github_img)
            icon_label.image = github_img  # Сохраняем ссылку
            icon_label.pack(side="left", padx=5)
        
        github_link = tk.Label(github_frame, text="github.com/yourusername/sonar", 
                               fg="blue", cursor="hand2", font=("Segoe UI", 9, "underline"))
        github_link.pack(side="left", padx=5)
        
        def open_github(event):
            import webbrowser
            webbrowser.open("https://github.com/yourusername/sonar")
        
        github_link.bind("<Button-1>", open_github)
        
        # C-ядро статус
        c_status = "✓ Активно (полная функциональность)" if CORE.available else "✗ Неактивно (Python fallback)"
        c_label = ttk.Label(main_frame, text=f"C-ядро: {c_status}", font=("Consolas", 8))
        c_label.pack(pady=(10, 5))
        
        # Логирование
        log_status = "✓ Включено (sonar.log / sonar_core.log)"
        log_label = ttk.Label(main_frame, text=log_status, font=("Consolas", 8))
        log_label.pack()
        
        # Кнопка закрытия
        ttk.Button(main_frame, text="Закрыть", command=about_window.destroy).pack(pady=15)
    
    def _set_device_status(self, card, text):
        """Устанавливает статус устройства."""
        card["status_var"].set(text)
    
    def _dev_log_write(self, text, tag="info"):
        """Запись в журнал устройств."""
        # Аналогично существующему коду...
        pass
    
    def _test_keyboard(self):
        """Тест клавиатуры."""
        # Аналогично существующему коду...
        pass
    
    def _test_mouse(self):
        """Тест мыши."""
        # Аналогично существующему коду...
        pass
    
    def _on_keypress(self, event):
        """Обработка нажатия клавиши."""
        # Аналогично существующему коду...
        pass
    
    def _on_mouseclick(self, event):
        """Обработка клика мыши."""
        # Аналогично существующему коду...
        pass
    
    def _on_scroll(self, event):
        """Обработка прокрутки."""
        # Аналогично существующему коду...
        pass
    
    def _test_mic(self):
        """Тест микрофона."""
        # Аналогично существующему коду...
        pass
    
    def _mic_worker(self):
        """Рабочий поток для теста микрофона."""
        # Аналогично существующему коду...
        pass


# Сохраняем существующий класс FileChecker (не меняем его, он уже есть в оригинале)
class FileChecker:
    # ... (оставляем существующий код из оригинального sonar.py)
    pass


def main():
    try:
        app = SonarApp()
        logger.info("Application started successfully")
        app.mainloop()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        messagebox.showerror("Критическая ошибка", f"Ошибка запуска:\n{e}")


if __name__ == "__main__":
    main()