#!/usr/bin/env python3
"""
Sonar — диагностика файлов и устройств
Интерфейс в стиле Windows (Диспетчер устройств / Диспетчер задач).
C-ядро подключается через ctypes для глубокого анализа.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, queue, os, sys, zipfile, tarfile
import gzip, bz2, lzma, zlib, struct, time, wave
import subprocess, platform, json, ctypes, tempfile
from pathlib import Path
from datetime import datetime

# ══════════════════════════════════════════════════════════════════════════════
#  C-ЯДРО  (sonar_core.so)
# ══════════════════════════════════════════════════════════════════════════════

def _find_lib():
    """Ищет скомпилированную библиотеку рядом со скриптом или в temp."""
    candidates = [
        Path(__file__).parent / "sonar_core.so",
        Path(tempfile.gettempdir()) / "sonar_core.so",
        Path("/home/claude/sonar_core.so"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None

def _compile_lib(dst: str) -> bool:
    """Компилирует C-ядро на лету, если gcc доступен."""
    src = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

double scan_entropy(const char *path){
    FILE *f=fopen(path,"rb"); if(!f)return -1.0;
    uint64_t freq[256]={0},total=0; uint8_t buf[65536]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){
        for(size_t i=0;i<n;i++) freq[buf[i]]++; total+=n; }
    fclose(f);
    if(total==0)return 0.0;
    double e=0.0;
    for(int i=0;i<256;i++){
        if(!freq[i])continue;
        double p=(double)freq[i]/(double)total; e-=p*log2(p); }
    return e;
}
double scan_nullratio(const char *path){
    FILE *f=fopen(path,"rb"); if(!f)return -1.0;
    uint64_t z=0,t=0; uint8_t buf[65536]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){
        for(size_t i=0;i<n;i++) if(!buf[i])z++; t+=n; }
    fclose(f); return t==0?0.0:(double)z/(double)t;
}
double scan_ascii_ratio(const char *path){
    FILE *f=fopen(path,"rb"); if(!f)return -1.0;
    uint64_t p=0,t=0; uint8_t buf[65536]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){
        for(size_t i=0;i<n;i++) if(buf[i]>=0x20&&buf[i]<=0x7E)p++; t+=n; }
    fclose(f); return t==0?0.0:(double)p/(double)t;
}
uint32_t calc_crc32(const char *path){
    static uint32_t tbl[256]; static int ready=0;
    if(!ready){ for(uint32_t i=0;i<256;i++){ uint32_t c=i;
        for(int k=0;k<8;k++) c=(c&1)?(0xEDB88320u^(c>>1)):(c>>1); tbl[i]=c; } ready=1; }
    FILE *f=fopen(path,"rb"); if(!f)return 0;
    uint32_t crc=0xFFFFFFFFu; uint8_t buf[65536]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)
        for(size_t i=0;i<n;i++) crc=tbl[(crc^buf[i])&0xFF]^(crc>>8);
    fclose(f); return crc^0xFFFFFFFFu;
}
int64_t scan_pattern(const char *path, uint32_t pattern){
    FILE *f=fopen(path,"rb"); if(!f)return -1;
    int64_t count=0; uint8_t buf[65539],pat[4]; size_t prev=0;
    pat[0]=(pattern>>24)&0xFF; pat[1]=(pattern>>16)&0xFF;
    pat[2]=(pattern>>8)&0xFF;  pat[3]=pattern&0xFF;
    while(1){ size_t n=fread(buf+prev,1,65536,f); if(!n)break;
        size_t tot=prev+n;
        for(size_t i=0;i+4<=tot;i++)
            if(buf[i]==pat[0]&&buf[i+1]==pat[1]&&buf[i+2]==pat[2]&&buf[i+3]==pat[3])count++;
        prev=(tot>=3)?3:tot; memmove(buf,buf+tot-prev,prev); }
    fclose(f); return count;
}
void byte_histogram(const char *path, uint64_t *out){
    memset(out,0,256*sizeof(uint64_t));
    FILE *f=fopen(path,"rb"); if(!f)return;
    uint8_t buf[65536]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)
        for(size_t i=0;i<n;i++) out[buf[i]]++;
    fclose(f);
}
"""
    src_path = dst.replace(".so", ".c")
    try:
        with open(src_path, "w") as f:
            f.write(src)
        ret = subprocess.run(
            ["gcc", "-O2", "-shared", "-fPIC", "-o", dst, src_path, "-lm"],
            capture_output=True, timeout=30)
        return ret.returncode == 0
    except Exception:
        return False


class SonarCore:
    """Обёртка над C-библиотекой с питоновым fallback."""

    def __init__(self):
        self._lib = None
        lib_path = _find_lib()
        if not lib_path:
            # Пробуем скомпилировать
            dst = str(Path(tempfile.gettempdir()) / "sonar_core.so")
            if _compile_lib(dst):
                lib_path = dst
        if lib_path:
            try:
                lib = ctypes.CDLL(lib_path)
                lib.scan_entropy.restype    = ctypes.c_double
                lib.scan_entropy.argtypes   = [ctypes.c_char_p]
                lib.scan_nullratio.restype  = ctypes.c_double
                lib.scan_nullratio.argtypes = [ctypes.c_char_p]
                lib.scan_ascii_ratio.restype  = ctypes.c_double
                lib.scan_ascii_ratio.argtypes = [ctypes.c_char_p]
                lib.calc_crc32.restype    = ctypes.c_uint32
                lib.calc_crc32.argtypes   = [ctypes.c_char_p]
                lib.scan_pattern.restype  = ctypes.c_int64
                lib.scan_pattern.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
                lib.byte_histogram.restype  = None
                lib.byte_histogram.argtypes = [ctypes.c_char_p,
                                               ctypes.POINTER(ctypes.c_uint64)]
                self._lib = lib
            except Exception:
                pass

    @property
    def available(self):
        return self._lib is not None

    def entropy(self, path: str) -> float:
        if self._lib:
            return self._lib.scan_entropy(path.encode())
        return self._py_entropy(path)

    def null_ratio(self, path: str) -> float:
        if self._lib:
            return self._lib.scan_nullratio(path.encode())
        return 0.0

    def ascii_ratio(self, path: str) -> float:
        if self._lib:
            return self._lib.scan_ascii_ratio(path.encode())
        return 0.0

    def crc32(self, path: str) -> int:
        if self._lib:
            return int(self._lib.calc_crc32(path.encode()))
        return 0

    def histogram(self, path: str) -> list:
        if self._lib:
            arr = (ctypes.c_uint64 * 256)()
            self._lib.byte_histogram(path.encode(), arr)
            return list(arr)
        return [0]*256

    # Python fallback для энтропии
    def _py_entropy(self, path):
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
#  ПРОВЕРКА ФАЙЛОВ
# ══════════════════════════════════════════════════════════════════════════════

class FileChecker:
    MAGIC = {
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff':       'JPEG',
        b'GIF87a':             'GIF',
        b'GIF89a':             'GIF',
        b'%PDF':               'PDF',
        b'PK\x03\x04':        'ZIP/DOCX',
        b'Rar!':               'RAR',
        b'\x1f\x8b':          'GZIP',
        b'BZh':               'BZIP2',
        b'\xfd7zXZ\x00':      'XZ',
        b'7z\xbc\xaf\x27\x1c':'7-ZIP',
        b'\x00\x00\x00 ftyp': 'MP4',
        b'RIFF':               'WAV/AVI',
        b'ID3':                'MP3',
        b'\xff\xfb':          'MP3',
        b'OggS':               'OGG',
        b'\x1aE\xdf\xa3':     'MKV/WEBM',
        b'fLaC':               'FLAC',
        b'MZ':                 'EXE/DLL',
        b'\x7fELF':           'ELF',
    }

    def check(self, path: str) -> dict:
        result = {
            "path": path, "name": os.path.basename(path),
            "size": 0, "type": "Неизвестно",
            "status": "ok", "issues": [], "details": [],
        }
        try:
            result["size"] = os.stat(path).st_size
        except OSError as e:
            result["status"] = "error"
            result["issues"].append(f"Нет доступа: {e}")
            return result

        if result["size"] == 0:
            result["status"] = "warn"
            result["issues"].append("Файл пустой (0 байт)")
            return result

        result["type"] = self._detect_type(path)
        ext = Path(path).suffix.lower()
        try:
            if ext in ('.zip','.docx','.xlsx','.pptx','.odt','.jar','.apk'):
                ok, detail = self._check_zip(path)
            elif ext in ('.tar','.tgz','.tar.gz','.tar.bz2','.tar.xz'):
                ok, detail = self._check_tar(path)
            elif ext == '.gz':
                ok, detail = self._check_gz(path)
            elif ext == '.bz2':
                ok, detail = self._check_bz2(path)
            elif ext in ('.xz','.lzma'):
                ok, detail = self._check_xz(path)
            elif ext in ('.png','.jpg','.jpeg','.gif','.bmp','.webp'):
                ok, detail = self._check_image(path)
            elif ext == '.pdf':
                ok, detail = self._check_pdf(path)
            elif ext == '.wav':
                ok, detail = self._check_wav(path)
            elif ext in ('.mp3','.ogg','.flac'):
                ok, detail = self._check_audio_generic(path)
            elif ext in ('.7z','.rar'):
                ok, detail = self._check_7z_rar(path)
            else:
                ok, detail = self._check_generic(path)
        except Exception as e:
            ok, detail = False, f"Ошибка проверки: {e}"

        result["details"].append(detail)
        result["status"] = "ok" if ok else "error"
        if not ok:
            result["issues"].append(detail)
        return result

    def deep_analyze(self, path: str, progress_cb=None) -> dict:
        """Режим детального разбора — использует C-ядро для полного анализа."""
        steps = [
            "Чтение заголовков и сигнатур",
            "Вычисление CRC-32 (C-ядро)",
            "Энтропия Шеннона (C-ядро)",
            "Анализ нулевых байт",
            "ASCII vs бинарный",
            "Байтовая гистограмма",
            "Структурная проверка",
            "Формирование отчёта",
        ]
        total = len(steps)

        def step(i, name):
            if progress_cb:
                progress_cb(i+1, total, name)
            time.sleep(0.05)   # даём GUI перерисоваться

        result = self.check(path)
        result["deep"] = {}

        step(0, steps[0])
        result["deep"]["type_detected"] = result["type"]

        step(1, steps[1])
        crc = CORE.crc32(path)
        result["deep"]["crc32"] = f"{crc:#010x}"

        step(2, steps[2])
        ent = CORE.entropy(path)
        result["deep"]["entropy"] = round(ent, 4)
        if ent > 7.5:
            result["deep"]["entropy_hint"] = "Очень высокая — вероятно сжатый/зашифрованный файл"
        elif ent > 6.0:
            result["deep"]["entropy_hint"] = "Высокая — смешанный контент или сжатие"
        elif ent > 4.0:
            result["deep"]["entropy_hint"] = "Средняя — текст или структурированные данные"
        else:
            result["deep"]["entropy_hint"] = "Низкая — простой текст или паттерн"

        step(3, steps[3])
        null_r = CORE.null_ratio(path)
        result["deep"]["null_ratio"] = round(null_r * 100, 2)
        if null_r > 0.3:
            result["deep"]["null_hint"] = "Много нулей — возможно повреждение или разреженный файл"
        else:
            result["deep"]["null_hint"] = "В норме"

        step(4, steps[4])
        asc_r = CORE.ascii_ratio(path)
        result["deep"]["ascii_ratio"] = round(asc_r * 100, 2)
        result["deep"]["content_class"] = "текстовый" if asc_r > 0.8 else "бинарный"

        step(5, steps[5])
        hist = CORE.histogram(path)
        total_bytes = sum(hist)
        top5 = sorted(range(256), key=lambda i: hist[i], reverse=True)[:5]
        result["deep"]["histogram"] = hist
        result["deep"]["top_bytes"] = [
            {"byte": f"0x{b:02X}", "char": chr(b) if 0x20<=b<=0x7E else "·",
             "count": hist[b],
             "pct": round(hist[b]/total_bytes*100, 2) if total_bytes else 0}
            for b in top5
        ]

        step(6, steps[6])
        # Дополнительные специфические проверки
        ext = Path(path).suffix.lower()
        extra = []
        if ext == '.png':
            extra = self._deep_png(path)
        elif ext in ('.jpg', '.jpeg'):
            extra = self._deep_jpeg(path)
        elif ext == '.pdf':
            extra = self._deep_pdf(path)
        elif ext in ('.zip','.docx','.xlsx'):
            extra = self._deep_zip(path)
        result["deep"]["extra"] = extra

        step(7, steps[7])
        # Итоговый вердикт
        problems = result["issues"][:]
        if null_r > 0.5:
            problems.append("Подозрительно много нулевых байт")
        result["deep"]["verdict_problems"] = problems
        result["deep"]["c_backend"] = CORE.available

        return result

    # ── Глубокие проверки по формату ──────────────────────────────────────

    def _deep_png(self, path):
        info = []
        try:
            with open(path,'rb') as f:
                data = f.read()
            pos = 8
            while pos < len(data)-8:
                length = struct.unpack('>I', data[pos:pos+4])[0]
                ctype = data[pos+4:pos+8].decode('ascii','replace')
                info.append(f"Чанк {ctype}: {length} байт")
                if ctype == 'IHDR' and length >= 13:
                    w,h,depth,color = struct.unpack('>IIBB', data[pos+8:pos+8+10])
                    color_types = {0:"Grayscale",2:"RGB",3:"Palette",4:"Gray+Alpha",6:"RGBA"}
                    info.append(f"  Размер: {w}×{h} пикс, {depth}bit, {color_types.get(color,color)}")
                if ctype == 'IEND':
                    break
                pos += 12 + length
        except Exception as e:
            info.append(f"Ошибка разбора PNG: {e}")
        return info

    def _deep_jpeg(self, path):
        info = []
        try:
            with open(path,'rb') as f:
                data = f.read()
            pos = 2
            while pos < len(data)-2:
                if data[pos] != 0xFF:
                    break
                marker = data[pos+1]
                if marker == 0xD9:
                    info.append("Маркер EOI найден — файл полный"); break
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    pos += 2; continue
                length = struct.unpack('>H', data[pos+2:pos+4])[0]
                if marker == 0xE0:
                    info.append(f"Сегмент APP0 (JFIF): {length} байт")
                elif marker == 0xE1:
                    info.append(f"Сегмент APP1 (EXIF/XMP): {length} байт")
                elif marker == 0xC0:
                    if pos+11 < len(data):
                        prec,h,w,comp = struct.unpack('>BHHB', data[pos+4:pos+11])
                        info.append(f"SOF0: {w}×{h} пикс, {comp} каналов, {prec}bit")
                pos += 2 + length
        except Exception as e:
            info.append(f"Ошибка разбора JPEG: {e}")
        return info

    def _deep_pdf(self, path):
        info = []
        try:
            with open(path,'rb') as f:
                head = f.read(32)
                f.seek(-2048, 2)
                tail = f.read()
            ver = head[5:8].decode('ascii','replace')
            info.append(f"Версия PDF: {ver}")
            # Считаем объекты
            obj_count = tail.count(b' obj') + tail.count(b'\nobj')
            if obj_count:
                info.append(f"Объектов в хвосте: ~{obj_count}")
            if b'/Encrypt' in tail:
                info.append("⚠ Файл зашифрован (содержит /Encrypt)")
            if b'/AcroForm' in tail or b'/AcroForm' in head:
                info.append("Содержит интерактивные формы (AcroForm)")
            if b'linearized' in tail.lower() or b'linearized' in head.lower():
                info.append("Линеаризован (быстрое открытие в браузере)")
        except Exception as e:
            info.append(f"Ошибка разбора PDF: {e}")
        return info

    def _deep_zip(self, path):
        info = []
        try:
            with zipfile.ZipFile(path,'r') as z:
                names = z.namelist()
                info.append(f"Файлов в архиве: {len(names)}")
                exts = {}
                for n in names:
                    e = Path(n).suffix.lower() or '(нет)'
                    exts[e] = exts.get(e, 0) + 1
                for ext, cnt in sorted(exts.items(), key=lambda x:-x[1])[:8]:
                    info.append(f"  {ext}: {cnt} файл(ов)")
                compressed = sum(i.compress_size for i in z.infolist())
                uncompressed = sum(i.file_size for i in z.infolist())
                if uncompressed > 0:
                    ratio = compressed/uncompressed*100
                    info.append(f"Сжатие: {_fmt(compressed)} → {_fmt(uncompressed)} ({ratio:.1f}%)")
        except Exception as e:
            info.append(f"Ошибка разбора ZIP: {e}")
        return info

    # ── Стандартные быстрые проверки ──────────────────────────────────────

    def _detect_type(self, path):
        try:
            with open(path,'rb') as f:
                h = f.read(16)
            for magic, name in self.MAGIC.items():
                if h[:len(magic)] == magic:
                    return name
        except Exception:
            pass
        return Path(path).suffix.upper().lstrip('.') or "Файл"

    def _check_zip(self, path):
        try:
            with zipfile.ZipFile(path,'r') as z:
                bad = z.testzip()
                if bad: return False, f"Повреждён файл внутри: {bad}"
                return True, f"ZIP исправен · {len(z.namelist())} файлов"
        except zipfile.BadZipFile as e: return False, f"Не ZIP или повреждён: {e}"
        except Exception as e: return False, f"Ошибка: {e}"

    def _check_tar(self, path):
        try:
            with tarfile.open(path,'r:*') as t:
                return True, f"TAR исправен · {len(t.getmembers())} объектов"
        except tarfile.TarError as e: return False, f"TAR повреждён: {e}"
        except Exception as e: return False, f"Ошибка: {e}"

    def _check_gz(self, path):
        try:
            with gzip.open(path,'rb') as f:
                size = sum(len(c) for c in iter(lambda: f.read(65536), b''))
            return True, f"GZIP исправен · распакованный: {_fmt(size)}"
        except Exception as e: return False, f"GZIP повреждён: {e}"

    def _check_bz2(self, path):
        try:
            with bz2.open(path,'rb') as f:
                size = sum(len(c) for c in iter(lambda: f.read(65536), b''))
            return True, f"BZ2 исправен · {_fmt(size)}"
        except Exception as e: return False, f"BZ2 повреждён: {e}"

    def _check_xz(self, path):
        try:
            with lzma.open(path,'rb') as f:
                size = sum(len(c) for c in iter(lambda: f.read(65536), b''))
            return True, f"XZ исправен · {_fmt(size)}"
        except Exception as e: return False, f"XZ повреждён: {e}"

    def _check_image(self, path):
        ext = Path(path).suffix.lower()
        try:
            with open(path,'rb') as f:
                data = f.read()
            if ext == '.png': return self._check_png_chunks(data)
            elif ext in ('.jpg','.jpeg'): return self._check_jpeg(data)
            return True, f"Изображение читается ({_fmt(len(data))})"
        except Exception as e: return False, f"Ошибка чтения: {e}"

    def _check_png_chunks(self, data):
        if data[:8] != b'\x89PNG\r\n\x1a\n': return False, "Неверная сигнатура PNG"
        pos, chunks, has_iend, errors = 8, 0, False, []
        while pos < len(data):
            if pos+8 > len(data): errors.append("Обрезан заголовок чанка"); break
            length = struct.unpack('>I', data[pos:pos+4])[0]
            ctype = data[pos+4:pos+8]
            chunk_data = data[pos+8:pos+8+length]
            end = pos+8+length
            if end+4 <= len(data):
                stored = struct.unpack('>I', data[end:end+4])[0]
                calc = zlib.crc32(ctype+chunk_data) & 0xFFFFFFFF
                if calc != stored:
                    errors.append(f"CRC ошибка в чанке {ctype.decode('ascii','replace')}")
            if ctype == b'IEND': has_iend = True; break
            chunks += 1
            pos += 12 + length
        if not has_iend: errors.append("Отсутствует маркер IEND")
        return (False, "; ".join(errors)) if errors else (True, f"PNG исправен · {chunks} чанков")

    def _check_jpeg(self, data):
        if data[:2] != b'\xff\xd8': return False, "Неверная сигнатура JPEG"
        if data[-2:] != b'\xff\xd9': return False, "JPEG обрезан (нет маркера EOI)"
        return True, f"JPEG исправен ({_fmt(len(data))})"

    def _check_pdf(self, path):
        try:
            with open(path,'rb') as f:
                if not f.read(8).startswith(b'%PDF'): return False, "Неверная сигнатура PDF"
                f.seek(-1024,2); tail=f.read()
            if b'%%EOF' not in tail and b'%EOF' not in tail:
                return False, "PDF обрезан (нет маркера EOF)"
            if b'xref' not in tail and b'startxref' not in tail:
                return False, "PDF: таблица ссылок отсутствует"
            return True, "PDF структура корректна"
        except Exception as e: return False, f"Ошибка: {e}"

    def _check_wav(self, path):
        try:
            with wave.open(path,'rb') as w:
                dur = w.getnframes()/w.getframerate() if w.getframerate() else 0
                return True, f"WAV: {w.getnchannels()}ch · {w.getframerate()} Гц · {dur:.1f}с"
        except wave.Error as e: return False, f"WAV повреждён: {e}"
        except Exception as e: return False, f"Ошибка: {e}"

    def _check_audio_generic(self, path):
        size = os.path.getsize(path)
        if size < 128: return False, "Файл слишком мал для аудио"
        return True, f"Аудио читается ({_fmt(size)})"

    def _check_7z_rar(self, path):
        ext = Path(path).suffix.lower()
        cmd = ['7z','t',path] if ext=='.7z' else ['unrar','t',path]
        label = '7-ZIP' if ext=='.7z' else 'RAR'
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            return (True,f"{label}: тест пройден") if r.returncode==0 else (False,f"{label}: повреждён")
        except Exception:
            return self._check_generic(path)

    def _check_generic(self, path):
        try:
            size = os.path.getsize(path)
            with open(path,'rb') as f:
                f.read(512)
                f.seek(max(0,size-512)); f.read(512)
            return True, f"Файл доступен ({_fmt(size)})"
        except Exception as e: return False, f"Файл нечитаем: {e}"


def _fmt(n):
    for u in ('Б','КБ','МБ','ГБ'):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} ТБ"


# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ ОКНО — стиль Windows (Диспетчер / Панель управления)
# ══════════════════════════════════════════════════════════════════════════════

WIN_BG    = "#F0F0F0"   # фон панелей Windows
TOOLBAR_H = 28          # высота тулбара

class SonarApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sonar — Диагностика файлов и устройств")
        self.geometry("960x620")
        self.minsize(720, 480)

        # Windows-тема
        style = ttk.Style(self)
        for theme in ("vista","winnative","xpnative","clam","default"):
            try: style.theme_use(theme); break
            except Exception: pass

        # Стили тулбара
        style.configure("Toolbar.TFrame",  background=WIN_BG, relief="raised", borderwidth=1)
        style.configure("Toolbar.TButton", padding=(6,2), relief="flat")
        style.configure("Status.TLabel",   background="#D4D0C8", relief="sunken",
                        padding=(4,1), font=("Segoe UI",8))
        style.configure("Title.TLabel",    font=("Segoe UI",9,"bold"))
        style.configure("Warn.TLabel",     foreground="#8B6000")
        style.configure("Error.TLabel",    foreground="#8B0000")
        style.configure("Ok.TLabel",       foreground="#006400")

        self._q        = queue.Queue()
        self._checker  = FileChecker()
        self._running  = False
        self._results  = []
        self._file_paths = []
        self._kbd_active   = False
        self._mouse_active = False

        self._build_ui()
        self._poll_queue()

    # ── Построение интерфейса ─────────────────────────────────────────────

    def _build_ui(self):
        # Меню (Windows-стиль)
        menubar = tk.Menu(self, relief="flat", tearoff=0)
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="Добавить файлы…",  accelerator="Ctrl+O",
                           command=self._add_files)
        m_file.add_command(label="Добавить папку…",  accelerator="Ctrl+D",
                           command=self._add_folder)
        m_file.add_separator()
        m_file.add_command(label="Сохранить отчёт…", accelerator="Ctrl+S",
                           command=self._export_report)
        m_file.add_separator()
        m_file.add_command(label="Выход", command=self.quit)
        menubar.add_cascade(label="Файл", menu=m_file)

        m_scan = tk.Menu(menubar, tearoff=0)
        m_scan.add_command(label="Сканировать",       accelerator="F5",
                           command=self._start_scan)
        m_scan.add_command(label="Детальный разбор…", accelerator="F6",
                           command=self._start_deep)
        m_scan.add_separator()
        m_scan.add_command(label="Очистить список",   command=self._clear)
        menubar.add_cascade(label="Сканирование", menu=m_scan)

        m_view = tk.Menu(menubar, tearoff=0)
        m_view.add_command(label="Показать детали выбранного", accelerator="Enter",
                           command=self._show_details)
        menubar.add_cascade(label="Вид", menu=m_view)

        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="О программе", command=self._about)
        menubar.add_cascade(label="Справка", menu=m_help)
        self.config(menu=menubar)

        self.bind("<Control-o>", lambda e: self._add_files())
        self.bind("<Control-d>", lambda e: self._add_folder())
        self.bind("<Control-s>", lambda e: self._export_report())
        self.bind("<F5>",        lambda e: self._start_scan())
        self.bind("<F6>",        lambda e: self._start_deep())
        self.bind("<Return>",    lambda e: self._show_details())

        # Тулбар — точно как Windows XP/7
        tb = tk.Frame(self, bg=WIN_BG, relief="raised", bd=1, height=TOOLBAR_H)
        tb.pack(fill="x", side="top")
        tb.pack_propagate(False)

        self._tb_btn("Добавить файлы",   "📄", tb, self._add_files)
        self._tb_btn("Добавить папку",   "📁", tb, self._add_folder)
        self._tb_sep(tb)
        self._tb_btn("Сканировать  [F5]","▶",  tb, self._start_scan)
        self._tb_btn("Детальный [F6]",   "🔬", tb, self._start_deep)
        self._tb_sep(tb)
        self._tb_btn("Очистить",         "✕",  tb, self._clear)
        self._tb_sep(tb)
        self._tb_btn("Отчёт",            "💾", tb, self._export_report)

        # C-бейдж справа
        c_lbl = tk.Label(tb, text=f"C-ядро: {'✓ активно' if CORE.available else '✗ нет gcc'}",
                         bg=WIN_BG,
                         fg="#006400" if CORE.available else "#8B0000",
                         font=("Consolas",8))
        c_lbl.pack(side="right", padx=8)

        # Notebook — вкладки
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        f_files = ttk.Frame(nb)
        f_dev   = ttk.Frame(nb)
        nb.add(f_files, text="   Файлы   ")
        nb.add(f_dev,   text="   Устройства   ")

        self._build_files_tab(f_files)
        self._build_devices_tab(f_dev)

        # Строка состояния (двойная, как в Explorer)
        sbar = tk.Frame(self, bg="#D4D0C8", relief="sunken", bd=1, height=20)
        sbar.pack(fill="x", side="bottom")
        sbar.pack_propagate(False)
        self._status_left  = tk.Label(sbar, text="Готов", bg="#D4D0C8",
                                       font=("Segoe UI",8), anchor="w")
        self._status_left.pack(side="left", fill="x", expand=True, padx=4)
        self._status_right = tk.Label(sbar, text="", bg="#D4D0C8",
                                       font=("Segoe UI",8), anchor="e")
        self._status_right.pack(side="right", padx=4)

    def _tb_btn(self, text, icon, parent, cmd):
        frm = tk.Frame(parent, bg=WIN_BG)
        frm.pack(side="left", padx=1, pady=2)
        btn = tk.Button(frm, text=f" {icon} {text} ", command=cmd,
                        relief="flat", bg=WIN_BG, activebackground="#C8D8E8",
                        font=("Segoe UI",8), cursor="hand2", bd=1,
                        highlightthickness=0)
        btn.pack()
        btn.bind("<Enter>", lambda e: btn.config(relief="raised"))
        btn.bind("<Leave>", lambda e: btn.config(relief="flat"))

    def _tb_sep(self, parent):
        sep = tk.Frame(parent, bg="#A0A0A0", width=1)
        sep.pack(side="left", fill="y", padx=3, pady=3)

    # ── Вкладка: Файлы ────────────────────────────────────────────────────

    def _build_files_tab(self, parent):
        # Левая панель — описание
        pane = tk.PanedWindow(parent, orient="horizontal", sashwidth=4,
                              bg="#C0C0C0", handlesize=0)
        pane.pack(fill="both", expand=True)

        # Таблица
        right = ttk.Frame(pane)
        pane.add(right, width=680)

        cols = ("status","name","type","size","detail")
        self._tree = ttk.Treeview(right, columns=cols, show="headings",
                                   selectmode="browse")
        self._tree.heading("status", text="")
        self._tree.heading("name",   text="Имя файла", anchor="w")
        self._tree.heading("type",   text="Тип", anchor="center")
        self._tree.heading("size",   text="Размер", anchor="e")
        self._tree.heading("detail", text="Результат проверки", anchor="w")

        self._tree.column("status", width=26,  stretch=False, anchor="center")
        self._tree.column("name",   width=210, minwidth=120)
        self._tree.column("type",   width=95,  minwidth=60,  anchor="center")
        self._tree.column("size",   width=80,  minwidth=60,  anchor="e")
        self._tree.column("detail", width=350, minwidth=100)

        self._tree.tag_configure("ok",      foreground="#005A00")
        self._tree.tag_configure("warn",    foreground="#7A5500")
        self._tree.tag_configure("err",     foreground="#8B0000")
        self._tree.tag_configure("pending", foreground="#606060")

        vsb = ttk.Scrollbar(right, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(right, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<Double-1>", lambda e: self._show_details())
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Правая панель — детали
        detail_pane = ttk.Frame(pane)
        pane.add(detail_pane, width=260)

        ttk.Label(detail_pane, text="Сведения о файле",
                  style="Title.TLabel").pack(anchor="w", padx=8, pady=(6,2))
        ttk.Separator(detail_pane, orient="horizontal").pack(fill="x", padx=4)

        self._detail_text = tk.Text(detail_pane, font=("Consolas",8),
                                     state="disabled", relief="flat",
                                     bg="#FAFAFA", wrap="word", cursor="arrow",
                                     padx=6, pady=4)
        self._detail_text.pack(fill="both", expand=True, padx=2, pady=2)

        # Прогресс-панель внизу
        prog_bar = ttk.Frame(parent)
        prog_bar.pack(fill="x", padx=4, pady=(2,4))

        self._prog_bar = ttk.Progressbar(prog_bar, mode="determinate", length=220)
        self._prog_bar.pack(side="left", padx=(0,6))
        self._prog_label = ttk.Label(prog_bar, text="Готов к сканированию")
        self._prog_label.pack(side="left")
        self._prog_counts = ttk.Label(prog_bar, text="")
        self._prog_counts.pack(side="right")

    def _on_tree_select(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        path = sel[0]
        res = next((r for r in self._results if r["path"] == path), None)
        if res:
            self._render_details(res)

    def _render_details(self, res):
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0","end")

        t = self._detail_text
        t.tag_configure("head",  font=("Segoe UI",8,"bold"))
        t.tag_configure("ok",    foreground="#005A00")
        t.tag_configure("warn",  foreground="#7A5500")
        t.tag_configure("err",   foreground="#8B0000")
        t.tag_configure("key",   font=("Consolas",7,"bold"))
        t.tag_configure("val",   font=("Consolas",7))

        status_map = {"ok": ("✓ ИСПРАВЕН","ok"), "warn":("⚠ ВНИМАНИЕ","warn"),
                      "error":("✗ ПОВРЕЖДЁН","err")}
        s_text, s_tag = status_map.get(res["status"], ("?",""))
        t.insert("end", f"{s_text}\n", (s_tag,"head"))
        t.insert("end", "─"*32+"\n", "key")
        t.insert("end", "Имя:  ", "key"); t.insert("end", res["name"]+"\n","val")
        t.insert("end", "Тип:  ", "key"); t.insert("end", res["type"]+"\n","val")
        t.insert("end", "Размер: ", "key"); t.insert("end", _fmt(res["size"])+"\n","val")

        if res.get("details"):
            t.insert("end", "\nДетали:\n","head")
            for d in res["details"]:
                t.insert("end", f"  {d}\n","val")

        if res.get("issues"):
            t.insert("end", "\nПроблемы:\n","head")
            for i in res["issues"]:
                t.insert("end", f"  ⚠ {i}\n",("warn","val"))

        deep = res.get("deep")
        if deep:
            t.insert("end", "\n🔬 Глубокий анализ:\n","head")
            t.insert("end", f"  CRC-32:    ","key")
            t.insert("end", deep.get("crc32","—")+"\n","val")
            t.insert("end", f"  Энтропия:  ","key")
            t.insert("end", f"{deep.get('entropy','—')} бит/байт\n","val")
            t.insert("end", f"             ","key")
            t.insert("end", deep.get("entropy_hint","—")+"\n","val")
            t.insert("end", f"  Нули:      ","key")
            t.insert("end", f"{deep.get('null_ratio','—')}%  {deep.get('null_hint','')}\n","val")
            t.insert("end", f"  ASCII:     ","key")
            t.insert("end", f"{deep.get('ascii_ratio','—')}% ({deep.get('content_class','—')})\n","val")
            t.insert("end", f"  C-ядро:    ","key")
            t.insert("end", ("✓ использовалось" if deep.get("c_backend") else "✗ Python fallback")+"\n","val")

            top = deep.get("top_bytes",[])
            if top:
                t.insert("end", "\n  Топ-5 байт:\n","head")
                for b in top:
                    t.insert("end",
                        f"    {b['byte']} '{b['char']}' → {b['count']} ({b['pct']}%)\n","val")

            extra = deep.get("extra",[])
            if extra:
                t.insert("end","\n  Структура:\n","head")
                for line in extra:
                    t.insert("end",f"  {line}\n","val")

            probs = deep.get("verdict_problems",[])
            if probs:
                t.insert("end","\n  ⚠ Проблемы:\n",("warn","head"))
                for p in probs:
                    t.insert("end",f"    • {p}\n",("warn","val"))
            else:
                t.insert("end","\n  ✓ Проблем не обнаружено\n",("ok","val"))

        t.configure(state="disabled")

    # ── Вкладка: Устройства ───────────────────────────────────────────────

    def _build_devices_tab(self, parent):
        # Заголовок в стиле Диспетчера устройств
        hdr = tk.Frame(parent, bg="#003399", height=32)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  Диагностика устройств ввода",
                 bg="#003399", fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left", padx=6, pady=4)

        # Тулбар устройств
        dtb = tk.Frame(parent, bg=WIN_BG, relief="raised", bd=1, height=26)
        dtb.pack(fill="x")
        dtb.pack_propagate(False)
        tk.Label(dtb, text=" Нажмите «Проверить», затем взаимодействуйте с устройством",
                 bg=WIN_BG, font=("Segoe UI",8), fg="#444").pack(side="left", padx=6)

        # Сплиттер — дерево слева, детали справа (как в Диспетчере устройств)
        pane = tk.PanedWindow(parent, orient="horizontal", sashwidth=4,
                              bg="#C0C0C0", handlesize=0)
        pane.pack(fill="both", expand=True)

        # Дерево устройств (левая часть)
        left = ttk.Frame(pane)
        pane.add(left, width=280)

        self._dev_tree = ttk.Treeview(left, show="tree", selectmode="browse")
        dev_vsb = ttk.Scrollbar(left, orient="vertical", command=self._dev_tree.yview)
        self._dev_tree.configure(yscrollcommand=dev_vsb.set)
        dev_vsb.pack(side="right", fill="y")
        self._dev_tree.pack(fill="both", expand=True)

        # Наполняем дерево
        root_id = self._dev_tree.insert("","end", text="💻 Этот компьютер", open=True)
        inp_id  = self._dev_tree.insert(root_id,"end",
                                         text="🖱 Устройства ввода", open=True)
        self._kbd_node   = self._dev_tree.insert(inp_id,"end",
                                                   text="⌨  Клавиатура  [не проверено]")
        self._mouse_node = self._dev_tree.insert(inp_id,"end",
                                                   text="🖱  Мышь  [не проверено]")
        aud_id  = self._dev_tree.insert(root_id,"end",
                                         text="🔊 Аудиоустройства", open=True)
        self._mic_node   = self._dev_tree.insert(aud_id,"end",
                                                   text="🎤  Микрофон  [не проверено]")

        # Правая часть — панель свойств устройства
        right = ttk.Frame(pane)
        pane.add(right)

        prop_hdr = tk.Frame(right, bg="#ECE9D8", relief="groove", bd=1, height=28)
        prop_hdr.pack(fill="x")
        prop_hdr.pack_propagate(False)
        tk.Label(prop_hdr, text=" Свойства устройства",
                 bg="#ECE9D8", font=("Segoe UI",8,"bold")).pack(side="left",padx=6,pady=4)

        # Карточки устройств в стиле Properties
        cards_frame = ttk.Frame(right)
        cards_frame.pack(fill="x", padx=8, pady=8)

        self._kbd_card   = self._make_device_card(cards_frame, "⌨ Клавиатура",   0)
        self._mouse_card = self._make_device_card(cards_frame, "🖱 Мышь",         1)
        self._mic_card   = self._make_device_card(cards_frame, "🎤 Микрофон",     2)

        self._kbd_card["btn"].configure(command=self._test_keyboard)
        self._mouse_card["btn"].configure(command=self._test_mouse)
        self._mic_card["btn"].configure(command=self._test_mic)

        # Журнал (как в Диспетчере устройств → вкладка «События»)
        evt_hdr = tk.Frame(right, bg="#ECE9D8", relief="groove", bd=1, height=22)
        evt_hdr.pack(fill="x", padx=8, pady=(8,0))
        evt_hdr.pack_propagate(False)
        tk.Label(evt_hdr, text=" Журнал событий",
                 bg="#ECE9D8", font=("Segoe UI",8,"bold")).pack(side="left",padx=6)

        log_frame = ttk.Frame(right)
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))

        self._dev_log = tk.Text(log_frame, height=7, state="disabled",
                                 font=("Consolas",8), relief="sunken", bd=1,
                                 wrap="word", cursor="arrow", bg="#FFFFFC")
        log_sb = ttk.Scrollbar(log_frame, command=self._dev_log.yview)
        self._dev_log.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self._dev_log.pack(fill="both", expand=True)

        self._dev_log.tag_config("ok",   foreground="#005A00")
        self._dev_log.tag_config("warn", foreground="#7A5500")
        self._dev_log.tag_config("err",  foreground="#8B0000")
        self._dev_log.tag_config("info", foreground="#00008B")

        # Бинды
        self.bind("<KeyPress>",    self._on_keypress)
        self.bind("<ButtonPress>", self._on_mouseclick)
        self.bind("<MouseWheel>",  self._on_scroll)
        self.bind("<Button-4>",    self._on_scroll)
        self.bind("<Button-5>",    self._on_scroll)

    def _make_device_card(self, parent, title, col):
        lf = ttk.LabelFrame(parent, text=title, padding=6)
        lf.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")
        parent.columnconfigure(col, weight=1)

        status_var = tk.StringVar(value="— не проверено —")
        lbl = ttk.Label(lf, textvariable=status_var, wraplength=140,
                         justify="center", font=("Segoe UI",8))
        lbl.pack(pady=(4,6), fill="x")

        btn = ttk.Button(lf, text="Проверить", width=14)
        btn.pack()

        return {"frame": lf, "status_var": status_var, "btn": btn}

    def _set_device_status(self, card, text):
        card["status_var"].set(text)

    # ── Логика файлов ─────────────────────────────────────────────────────

    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Добавить файлы для проверки")
        added = 0
        for p in paths:
            if p not in self._file_paths:
                self._file_paths.append(p)
                self._insert_pending(p)
                added += 1
        if added:
            self._set_status(f"Добавлено {added} файл(ов). Итого: {len(self._file_paths)}")

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Добавить папку")
        if not folder:
            return
        added = 0
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                p = os.path.join(root, fname)
                if p not in self._file_paths:
                    self._file_paths.append(p)
                    self._insert_pending(p)
                    added += 1
        self._set_status(f"Добавлено из папки: {added} файл(ов)")

    def _insert_pending(self, path):
        name = os.path.basename(path)
        size = _fmt(os.path.getsize(path)) if os.path.exists(path) else "—"
        self._tree.insert("","end", iid=path,
                          values=("○",name,"—",size,"ожидание…"),
                          tags=("pending",))

    def _start_scan(self):
        if self._running:
            messagebox.showinfo("Sonar", "Сканирование уже выполняется…")
            return
        if not self._file_paths:
            messagebox.showinfo("Sonar",
                "Список файлов пуст.\n\nДобавьте файлы кнопкой «Добавить файлы» или «Добавить папку».")
            return
        self._running = True
        self._results = []
        self._prog_bar.configure(maximum=len(self._file_paths), value=0)
        self._prog_label.configure(text="Сканирование…")
        self._prog_counts.configure(text="")
        self._set_status(f"Сканирование {len(self._file_paths)} файлов…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        total = len(self._file_paths)
        for i, path in enumerate(self._file_paths):
            result = self._checker.check(path)
            self._results.append(result)
            self._q.put(("result", i+1, total, result))
            time.sleep(0)
        self._q.put(("done", total))

    # ── Режим детального разбора ──────────────────────────────────────────

    def _start_deep(self):
        sel = self._tree.selection()
        if not sel:
            if not self._file_paths:
                messagebox.showinfo("Sonar",
                    "Нет файлов для анализа.\n\nДобавьте файлы, затем нажмите F6 или выберите файл и нажмите F6.")
                return
            # Анализируем все файлы
            self._start_deep_all()
            return
        path = sel[0]
        self._start_deep_single(path)

    def _start_deep_single(self, path):
        if self._running:
            messagebox.showinfo("Sonar", "Подождите завершения текущей операции.")
            return
        self._running = True
        self._prog_bar.configure(maximum=8, value=0)
        self._prog_label.configure(text="🔬 Детальный анализ…")
        self._set_status(f"Глубокий разбор: {os.path.basename(path)}")

        def worker():
            def progress(done, total, step_name):
                self._q.put(("deep_progress", done, total, step_name))
            result = self._checker.deep_analyze(path, progress_cb=progress)
            # Обновляем или добавляем в results
            existing = next((r for r in self._results if r["path"]==path), None)
            if existing:
                existing.update(result)
            else:
                self._results.append(result)
            self._q.put(("deep_done", result))

        threading.Thread(target=worker, daemon=True).start()

    def _start_deep_all(self):
        if self._running: return
        self._running = True
        total_files = len(self._file_paths)
        self._results = []
        self._prog_bar.configure(maximum=total_files * 8, value=0)
        self._prog_label.configure(text="🔬 Детальный анализ…")

        def worker():
            for i, path in enumerate(self._file_paths):
                def progress(done, total_steps, step_name, _i=i):
                    self._q.put(("deep_progress_multi",
                                 _i*8+done, total_files*8, path, step_name))
                result = self._checker.deep_analyze(path, progress_cb=progress)
                self._results.append(result)
                self._q.put(("result", i+1, total_files, result))
            self._q.put(("deep_all_done", total_files))

        threading.Thread(target=worker, daemon=True).start()

    # ── Очередь сообщений ─────────────────────────────────────────────────

    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                tag = msg[0]

                if tag == "result":
                    _, done, total, result = msg
                    self._update_row(result)
                    self._prog_bar.configure(value=done)
                    self._prog_label.configure(text=f"Проверено: {done} / {total}")

                elif tag == "done":
                    self._scan_done(msg[1])

                elif tag == "deep_progress":
                    _, done, total, step_name = msg
                    self._prog_bar.configure(value=done)
                    self._prog_label.configure(text=f"🔬 {step_name}")
                    self._set_status(step_name)

                elif tag == "deep_progress_multi":
                    _, done, total, path, step_name = msg
                    self._prog_bar.configure(value=done)
                    pct = int(done/total*100) if total else 0
                    self._prog_label.configure(
                        text=f"🔬 {os.path.basename(path)}: {step_name} ({pct}%)")

                elif tag == "deep_done":
                    result = msg[1]
                    self._update_row(result)
                    self._running = False
                    self._prog_label.configure(text="Детальный анализ завершён")
                    self._set_status("Детальный анализ завершён. Дважды щёлкните по файлу для просмотра.")
                    # Показываем детали
                    self._render_details(result)

                elif tag == "deep_all_done":
                    n = msg[1]
                    self._running = False
                    ok   = sum(1 for r in self._results if r["status"]=="ok")
                    warn = sum(1 for r in self._results if r["status"]=="warn")
                    err  = sum(1 for r in self._results if r["status"]=="error")
                    self._prog_label.configure(text=f"Глубокий анализ завершён · {n} файлов")
                    self._prog_counts.configure(text=f"✓ {ok}  ⚠ {warn}  ✗ {err}")

                elif tag == "mic_result":
                    _, text, log_text, log_tag = msg
                    self._set_device_status(self._mic_card, text)
                    self._mic_card["btn"].configure(state="normal")
                    self._dev_log_write(log_text, log_tag)
                    node_icon = "✓" if log_tag=="ok" else "⚠"
                    self._dev_tree.item(self._mic_node,
                        text=f"🎤  Микрофон  [{node_icon} {text}]")

        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _update_row(self, r):
        icon = {"ok":"✓","warn":"⚠","error":"✗"}.get(r["status"],"?")
        s_txt = {"ok":"Исправен","warn":"Внимание","error":"Повреждён"}.get(r["status"],"?")
        detail = (r["details"]+r["issues"]+["—"])[0]
        if r.get("deep"):
            detail = f"[🔬] {detail}"
        tag = r["status"] if r["status"] in ("ok","warn") else "err"
        try:
            self._tree.item(r["path"],
                            values=(icon, r["name"], r["type"], _fmt(r["size"]), detail),
                            tags=(tag,))
        except Exception:
            pass

    def _scan_done(self, total):
        self._running = False
        ok   = sum(1 for r in self._results if r["status"]=="ok")
        warn = sum(1 for r in self._results if r["status"]=="warn")
        err  = sum(1 for r in self._results if r["status"]=="error")
        self._prog_label.configure(text=f"Готово: {total} файлов")
        self._prog_counts.configure(
            text=f"✓ {ok}  ⚠ {warn}  ✗ {err}" +
                 (f"  —  Повреждено: {err}" if err else "  —  Все файлы исправны"))
        self._set_status(
            f"Сканирование завершено: {total} файлов. "
            f"Исправно: {ok}, Предупреждения: {warn}, Повреждено: {err}")

    def _clear(self):
        if self._running:
            messagebox.showinfo("Sonar","Дождитесь завершения операции.")
            return
        self._file_paths.clear()
        self._results.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0","end")
        self._detail_text.configure(state="disabled")
        self._prog_label.configure(text="Готов к сканированию")
        self._prog_counts.configure(text="")
        self._prog_bar.configure(value=0)
        self._set_status("Список очищен")

    def _show_details(self):
        sel = self._tree.selection()
        if not sel:
            return
        path = sel[0]
        res = next((r for r in self._results if r["path"]==path), None)
        if res:
            self._render_details(res)
        else:
            # Файл ещё не сканировался — запускаем глубокий разбор
            self._start_deep_single(path)

    def _export_report(self):
        if not self._results:
            messagebox.showinfo("Sonar","Нет данных. Выполните сканирование.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый отчёт","*.txt"),("JSON","*.json")],
            initialfile=f"sonar_report_{datetime.now():%Y%m%d_%H%M%S}")
        if not path:
            return
        if path.endswith(".json"):
            # Гистограмму не сериализуем в JSON — слишком большая
            safe = []
            for r in self._results:
                rc = dict(r)
                if "deep" in rc and "histogram" in rc["deep"]:
                    rc["deep"] = dict(rc["deep"])
                    del rc["deep"]["histogram"]
                safe.append(rc)
            with open(path,"w",encoding="utf-8") as f:
                json.dump(safe, f, ensure_ascii=False, indent=2)
        else:
            with open(path,"w",encoding="utf-8") as f:
                f.write(f"SONAR — Отчёт диагностики\n")
                f.write(f"Дата: {datetime.now():%d.%m.%Y %H:%M:%S}\n")
                f.write(f"C-ядро: {'активно' if CORE.available else 'не найдено (Python fallback)'}\n")
                f.write("="*70+"\n\n")
                for r in self._results:
                    s = {"ok":"ИСПРАВЕН","warn":"ВНИМАНИЕ","error":"ПОВРЕЖДЁН"}.get(r["status"],"?")
                    f.write(f"[{s}] {r['path']}\n")
                    f.write(f"  Тип: {r['type']}  Размер: {_fmt(r['size'])}\n")
                    for d in r["details"]:
                        f.write(f"  • {d}\n")
                    for i in r["issues"]:
                        f.write(f"  ! {i}\n")
                    deep = r.get("deep")
                    if deep:
                        f.write(f"  [Глубокий анализ]\n")
                        f.write(f"    CRC-32:   {deep.get('crc32','—')}\n")
                        f.write(f"    Энтропия: {deep.get('entropy','—')} бит/байт — {deep.get('entropy_hint','')}\n")
                        f.write(f"    Нули:     {deep.get('null_ratio','—')}% — {deep.get('null_hint','')}\n")
                        f.write(f"    ASCII:    {deep.get('ascii_ratio','—')}% ({deep.get('content_class','')})\n")
                        for line in deep.get("extra",[]):
                            f.write(f"    {line}\n")
                    f.write("\n")
        messagebox.showinfo("Sonar",f"Отчёт сохранён:\n{path}")

    # ── Устройства ────────────────────────────────────────────────────────

    def _dev_log_write(self, text, tag="info"):
        self._dev_log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._dev_log.insert("end", f"[{ts}]  {text}\n", tag)
        self._dev_log.see("end")
        self._dev_log.configure(state="disabled")

    def _test_keyboard(self):
        self._dev_log_write("Ожидание нажатия клавиши…","info")
        self._kbd_active = True
        self._set_device_status(self._kbd_card,"Нажмите любую клавишу…")
        self._dev_tree.item(self._kbd_node, text="⌨  Клавиатура  [ожидание…]")

    def _on_keypress(self, event):
        if self._kbd_active:
            self._kbd_active = False
            key = event.keysym
            self._set_device_status(self._kbd_card, f"✓ Работает  [{key}]")
            self._dev_log_write(f"Клавиатура: клавиша «{key}» зарегистрирована","ok")
            self._dev_tree.item(self._kbd_node,
                text=f"⌨  Клавиатура  [✓ {key}]")

    def _test_mouse(self):
        self._dev_log_write("Ожидание нажатия или прокрутки мыши…","info")
        self._mouse_active = True
        self._set_device_status(self._mouse_card,"Нажмите кнопку или прокрутите…")
        self._dev_tree.item(self._mouse_node, text="🖱  Мышь  [ожидание…]")

    def _on_mouseclick(self, event):
        if self._mouse_active:
            self._mouse_active = False
            btn_names = {1:"Левая",2:"Средняя",3:"Правая"}
            btn = btn_names.get(event.num, f"#{event.num}")
            self._set_device_status(self._mouse_card, f"✓ Работает  [{btn} кнопка]")
            self._dev_log_write(
                f"Мышь: {btn} кнопка · позиция ({event.x_root}, {event.y_root})","ok")
            self._dev_tree.item(self._mouse_node,
                text=f"🖱  Мышь  [✓ {btn} кнопка]")

    def _on_scroll(self, event):
        if self._mouse_active:
            self._mouse_active = False
            self._set_device_status(self._mouse_card,"✓ Колесо работает")
            self._dev_log_write("Мышь: прокрутка колеса зарегистрирована","ok")
            self._dev_tree.item(self._mouse_node, text="🖱  Мышь  [✓ колесо]")

    def _test_mic(self):
        self._set_device_status(self._mic_card,"Запись 2 сек…")
        self._mic_card["btn"].configure(state="disabled")
        self._dev_log_write("Микрофон: начало тестовой записи (2 сек)…","info")
        self._dev_tree.item(self._mic_node, text="🎤  Микрофон  [запись…]")
        threading.Thread(target=self._mic_worker, daemon=True).start()

    def _mic_worker(self):
        try:
            try:
                import sounddevice as sd, numpy as np
                rec = sd.rec(int(2*44100), samplerate=44100, channels=1, dtype='int16')
                sd.wait()
                peak = int(np.abs(rec).max())
                rms  = int(np.sqrt(np.mean(rec.astype(np.float32)**2)))
                if peak < 50:
                    self._q.put(("mic_result","⚠ Тихо / нет сигнала",
                                 f"Микрофон: пик={peak}, RMS={rms}","warn"))
                else:
                    self._q.put(("mic_result",f"✓ Работает  Пик: {peak}",
                                 f"Микрофон: пик={peak}, RMS={rms}","ok"))
                return
            except ImportError:
                pass

            if platform.system() == "Linux":
                r = subprocess.run(
                    ["arecord","-d","2","-f","S16_LE","-r","44100",
                     "-c","1","/tmp/sonar_mic_test.wav"],
                    capture_output=True, timeout=5)
                if r.returncode == 0 and os.path.exists("/tmp/sonar_mic_test.wav"):
                    size = os.path.getsize("/tmp/sonar_mic_test.wav")
                    os.remove("/tmp/sonar_mic_test.wav")
                    if size > 1000:
                        self._q.put(("mic_result","✓ Работает",
                                     "Микрофон: запись успешна","ok"))
                    else:
                        self._q.put(("mic_result","⚠ Нет сигнала",
                                     "Микрофон: пустая запись","warn"))
                    return

            if platform.system() == "Windows":
                r = subprocess.run(
                    ["powershell","-Command",
                     "Get-PnpDevice -Class AudioEndpoint | Where Status -eq OK | Select Name"],
                    capture_output=True, timeout=8, text=True)
                if r.returncode==0 and r.stdout.strip():
                    name = r.stdout.strip().splitlines()[-1]
                    self._q.put(("mic_result","✓ Аудиоустройства найдены",name,"ok"))
                    return

            self._q.put(("mic_result","? Невозможно проверить",
                         "Установите: pip install sounddevice","warn"))
        except Exception as e:
            self._q.put(("mic_result",f"✗ Ошибка: {e}",str(e),"err"))

    # ── Вспомогательное ───────────────────────────────────────────────────

    def _set_status(self, text):
        self._status_left.configure(text=f"  {text}")
        ts = datetime.now().strftime("%H:%M:%S")
        self._status_right.configure(text=f"{ts}  ")

    def _about(self):
        c_status = "активно (gcc)" if CORE.available else "недоступно (Python fallback)"
        messagebox.showinfo("О программе — Sonar",
            "Sonar — Диагностика файлов и устройств\n\n"
            "Возможности:\n"
            "  • Быстрая проверка целостности файлов\n"
            "  • Детальный разбор: энтропия, CRC-32, байтовая статистика\n"
            "  • Диагностика устройств ввода\n"
            "  • Экспорт отчёта в TXT / JSON\n\n"
            f"C-ядро (sonar_core.so): {c_status}\n"
            "Функции C-ядра:\n"
            "  scan_entropy()  — энтропия Шеннона\n"
            "  calc_crc32()    — контрольная сумма\n"
            "  scan_nullratio()— доля нулевых байт\n"
            "  byte_histogram()— частотный анализ\n\n"
            "Горячие клавиши:\n"
            "  F5  — быстрое сканирование\n"
            "  F6  — детальный разбор\n"
            "  Enter — свойства выбранного файла\n"
            "  Ctrl+O — добавить файлы\n"
            "  Ctrl+S — сохранить отчёт")


def main():
    app = SonarApp()
    app.mainloop()


if __name__ == "__main__":
    main()