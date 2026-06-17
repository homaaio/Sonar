#!/usr/bin/env python3
"""
Sonar v3.0 — Комплексная диагностика файлов и устройств
═══════════════════════════════════════════════════════
Архитектура:
  Python  — UI, оркестрация, лёгкие задачи
  C       — энтропия, CRC32, гистограммы, LSB-анализ (sonar_core.dll/.so)
  HTML/JS — интерактивный HTML-отчёт с графиками (Chart.js)

Функции:
  • Анализ файлов: метаданные EXIF/ID3/DOCX/PDF, структура архивов (рекурсивно)
  • Сравнение файлов: построчный diff с подсветкой (ПКМ → Сравнить)
  • Восстановление заголовков (ПКМ → Восстановить)
  • Стеганография: LSB-анализ изображений
  • Deep scan: база 23 сигнатур вирусов из JSON
  • Устройства: дисплей, батарея, Wi-Fi, Bluetooth, USB, динамики, мышь, клавиатура, микрофон
  • Мониторинг: real-time слежение за файлами
  • Планировщик: автоматическое сканирование по расписанию
  • Многопоточный анализ
  • Drag & Drop
  • Экспорт: TXT / JSON / HTML (Chart.js)
  • Языки: RU / EN / FR   Темы: светлая / тёмная
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading, queue, os, sys, zipfile, tarfile, gzip, bz2, lzma
import zlib, struct, time, wave, subprocess, platform, json, ctypes
import tempfile, hashlib, re, webbrowser, difflib, socket, math
import shutil, copy, traceback
from pathlib import Path
from datetime import datetime, timedelta

# ──────────────────────────────────────────────────────────────────────────────
#  ОПЦИОНАЛЬНЫЕ ЗАВИСИМОСТИ
# ──────────────────────────────────────────────────────────────────────────────
try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import mutagen
    from mutagen.id3 import ID3, ID3NoHeaderError
    from mutagen.mp3 import MP3
    from mutagen.flac import FLAC
    from mutagen.ogg import OggFileType
    HAS_MUTAGEN = True
except ImportError:
    HAS_MUTAGEN = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ──────────────────────────────────────────────────────────────────────────────
#  ПУТИ
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
VIRUS_DB   = BASE_DIR / "virus_db" / "signatures.json"
ASSETS_DIR = BASE_DIR / "assets"

# ══════════════════════════════════════════════════════════════════════════════
#  C-ЯДРО
# ══════════════════════════════════════════════════════════════════════════════
_C_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

double scan_entropy(const char *path){
    FILE *f=fopen(path,"rb");if(!f)return -1.0;
    uint64_t freq[256]={0},total=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)freq[buf[i]]++;total+=n;}
    fclose(f);if(total==0)return 0.0;
    double e=0.0;
    for(int i=0;i<256;i++){if(!freq[i])continue;double p=(double)freq[i]/(double)total;e-=p*log2(p);}
    return e;
}
double scan_nullratio(const char *p){
    FILE *f=fopen(p,"rb");if(!f)return -1.0;
    uint64_t z=0,t=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)if(!buf[i])z++;t+=n;}
    fclose(f);return t==0?0.0:(double)z/(double)t;
}
double scan_ascii_ratio(const char *p){
    FILE *f=fopen(p,"rb");if(!f)return -1.0;
    uint64_t a=0,t=0;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){for(size_t i=0;i<n;i++)if(buf[i]>=0x20&&buf[i]<=0x7E)a++;t+=n;}
    fclose(f);return t==0?0.0:(double)a/(double)t;
}
uint32_t calc_crc32(const char *p){
    static uint32_t tbl[256];static int ready=0;
    if(!ready){for(uint32_t i=0;i<256;i++){uint32_t c=i;for(int k=0;k<8;k++)c=(c&1)?(0xEDB88320u^(c>>1)):(c>>1);tbl[i]=c;}ready=1;}
    FILE *f=fopen(p,"rb");if(!f)return 0;
    uint32_t crc=0xFFFFFFFFu;uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)for(size_t i=0;i<n;i++)crc=tbl[(crc^buf[i])&0xFF]^(crc>>8);
    fclose(f);return crc^0xFFFFFFFFu;
}
void byte_histogram(const char *p, uint64_t *out){
    memset(out,0,256*sizeof(uint64_t));
    FILE *f=fopen(p,"rb");if(!f)return;
    uint8_t buf[65536];size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0)for(size_t i=0;i<n;i++)out[buf[i]]++;
    fclose(f);
}
double lsb_randomness(const uint8_t *pixels, int64_t count){
    if(count<2)return 0.0;
    int64_t diff=0;
    for(int64_t i=0;i+1<count;i++)diff+=((pixels[i]^pixels[i+1])&1);
    return (double)diff/(double)(count-1);
}
"""

def _find_lib():
    for name in ("sonar_core.dll","sonar_core.so"):
        for d in (BASE_DIR, BASE_DIR.parent, Path(tempfile.gettempdir())):
            p = d / name
            if p.exists(): return str(p)
    return None

def _compile_lib():
    is_win = platform.system()=="Windows"
    ext = ".dll" if is_win else ".so"
    dst = str(Path(tempfile.gettempdir()) / f"sonar_core{ext}")
    src = dst.replace(ext,".c")
    try:
        with open(src,"w") as f: f.write(_C_SRC)
        cmd = ["gcc","-O2","-shared","-o",dst,src,"-lm"]
        if not is_win: cmd.insert(3,"-fPIC")
        r = subprocess.run(cmd,capture_output=True,timeout=30)
        return dst if r.returncode==0 else None
    except: return None

class SonarCore:
    def __init__(self):
        self._lib=None
        lp=_find_lib() or _compile_lib()
        if lp:
            try:
                lib=ctypes.CDLL(lp)
                def _set(fn,ret,*args):
                    f=getattr(lib,fn); f.restype=ret; f.argtypes=list(args)
                _set("scan_entropy",   ctypes.c_double, ctypes.c_char_p)
                _set("scan_nullratio", ctypes.c_double, ctypes.c_char_p)
                _set("scan_ascii_ratio",ctypes.c_double,ctypes.c_char_p)
                _set("calc_crc32",     ctypes.c_uint32, ctypes.c_char_p)
                _set("byte_histogram", None, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint64))
                _set("lsb_randomness", ctypes.c_double, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int64)
                self._lib=lib
            except: pass

    @property
    def available(self): return self._lib is not None

    def entropy(self,path):
        if self._lib: return float(self._lib.scan_entropy(path.encode()))
        return self._py_entropy(path)
    def null_ratio(self,path):
        if self._lib: return float(self._lib.scan_nullratio(path.encode()))
        return 0.0
    def ascii_ratio(self,path):
        if self._lib: return float(self._lib.scan_ascii_ratio(path.encode()))
        return 0.0
    def crc32(self,path):
        if self._lib: return int(self._lib.calc_crc32(path.encode()))
        return 0
    def histogram(self,path):
        if self._lib:
            arr=(ctypes.c_uint64*256)()
            self._lib.byte_histogram(path.encode(),arr)
            return list(arr)
        return [0]*256
    def lsb_randomness(self,pixels_bytes):
        if self._lib and pixels_bytes:
            arr=(ctypes.c_uint8*len(pixels_bytes))(*pixels_bytes)
            return float(self._lib.lsb_randomness(arr,len(pixels_bytes)))
        return self._py_lsb(pixels_bytes)
    def _py_entropy(self,path):
        try:
            freq=[0]*256
            with open(path,'rb') as f:
                for chunk in iter(lambda:f.read(65536),b''):
                    for b in chunk: freq[b]+=1
            total=sum(freq)
            if not total: return 0.0
            return -sum(p/total*math.log2(p/total) for p in freq if p)
        except: return 0.0
    def _py_lsb(self,pixels):
        if len(pixels)<2: return 0.0
        return sum((pixels[i]^pixels[i+1])&1 for i in range(len(pixels)-1))/(len(pixels)-1)

CORE = SonarCore()

# ══════════════════════════════════════════════════════════════════════════════
#  БАЗА СИГНАТУР ВИРУСОВ
# ══════════════════════════════════════════════════════════════════════════════
class VirusDB:
    def __init__(self):
        self.signatures=[]
        self.dangerous_ext=set()
        self.suspicious_ext=set()
        self.known_malware=set()
        self._load()

    def _load(self):
        try:
            if VIRUS_DB.exists():
                with open(VIRUS_DB,'r',encoding='utf-8') as f:
                    db=json.load(f)
                for sig in db.get('byte_signatures',[]):
                    try:
                        b=bytes.fromhex(sig['hex'].replace(' ',''))
                        self.signatures.append((b,sig['name'],sig['severity'],sig['type']))
                    except: pass
                self.dangerous_ext = set(db.get('dangerous_extensions',[]))
                self.suspicious_ext = set(db.get('suspicious_extensions',[]))
                self.known_malware  = set(db.get('known_malware_sha256',[]))
        except Exception as e:
            print(f"VirusDB load error: {e}")

    def scan(self, path:str, first64k:bytes) -> list:
        """Возвращает список найденных угроз."""
        found=[]
        # Байтовые сигнатуры
        for sig,name,sev,typ in self.signatures:
            if sig in first64k:
                found.append({"name":name,"severity":sev,"type":typ})
        # SHA256 по всему файлу
        try:
            sha=hashlib.sha256()
            with open(path,'rb') as f:
                for chunk in iter(lambda:f.read(65536),b''): sha.update(chunk)
            digest=sha.hexdigest()
            if digest in self.known_malware:
                found.append({"name":f"Известный малварь (SHA256: {digest[:16]}…)","severity":"danger","type":"known_malware"})
        except: pass
        return found

VDB = VirusDB()

# ══════════════════════════════════════════════════════════════════════════════
#  УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════════════════
def _fmt(n):
    for u in ('Б','КБ','МБ','ГБ'):
        if n<1024: return f"{n:.1f} {u}"
        n/=1024
    return f"{n:.1f} ТБ"

def _ts(): return datetime.now().strftime("%H:%M:%S")
def _dt(): return datetime.now().strftime("%d.%m.%Y %H:%M:%S")

# ══════════════════════════════════════════════════════════════════════════════
#  МЕТАДАННЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class MetaReader:
    """Читает EXIF, ID3, PDF, DOCX метаданные."""

    def read(self, path:str) -> dict:
        ext=Path(path).suffix.lower()
        if ext in ('.jpg','.jpeg','.png','.tiff','.webp') and HAS_PIL:
            return self._exif(path)
        elif ext in ('.mp3','.flac','.ogg','.m4a') and HAS_MUTAGEN:
            return self._id3(path)
        elif ext=='.pdf':
            return self._pdf(path)
        elif ext in('.docx','.xlsx','.pptx'):
            return self._ooxml(path)
        return {}

    def _exif(self,path):
        meta={"format":"EXIF/Image"}
        try:
            img=Image.open(path)
            meta["mode"]      = img.mode
            meta["size"]      = f"{img.width}×{img.height}"
            meta["format_str"]= img.format or "?"
            raw=img._getexif() if hasattr(img,'_getexif') else None
            if raw:
                for tag,val in raw.items():
                    name=ExifTags.TAGS.get(tag,str(tag))
                    if isinstance(val,bytes): continue
                    meta[name]=str(val)[:120]
        except Exception as e: meta["error"]=str(e)
        return meta

    def _id3(self,path):
        meta={"format":"ID3/Audio"}
        try:
            audio=mutagen.File(path)
            if audio:
                if hasattr(audio,'info'):
                    info=audio.info
                    if hasattr(info,'length'):   meta["duration"]=f"{info.length:.1f}s"
                    if hasattr(info,'bitrate'):  meta["bitrate"] =f"{info.bitrate} bps"
                    if hasattr(info,'sample_rate'): meta["sample_rate"]=f"{info.sample_rate} Hz"
                for k,v in audio.items():
                    meta[str(k)]=str(v)[:120]
        except Exception as e: meta["error"]=str(e)
        return meta

    def _pdf(self,path):
        meta={"format":"PDF"}
        try:
            with open(path,'rb') as f:
                data=f.read(4096)
            # Ищем /Info
            for field in (b'Title',b'Author',b'Creator',b'Producer',b'Subject',b'Keywords',b'CreationDate'):
                pat=b'/'+field+b' ('
                idx=data.find(pat)
                if idx>=0:
                    start=idx+len(pat); end=data.find(b')',start)
                    if end>start:
                        val=data[start:end].decode('latin-1','replace')[:100]
                        meta[field.decode()]=val
            # Версия
            if data[:4]==b'%PDF': meta["version"]=data[5:8].decode('ascii','replace')
        except Exception as e: meta["error"]=str(e)
        return meta

    def _ooxml(self,path):
        meta={"format":"OOXML"}
        try:
            with zipfile.ZipFile(path,'r') as z:
                if 'docProps/core.xml' in z.namelist():
                    xml=z.read('docProps/core.xml').decode('utf-8','replace')
                    for tag in ('dc:title','dc:creator','cp:lastModifiedBy','dcterms:created',
                                'dcterms:modified','cp:revision','cp:lastPrinted'):
                        m=re.search(rf'<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>', xml)
                        if m: meta[tag.split(':')[1]]=m.group(1)[:100]
                if 'docProps/app.xml' in z.namelist():
                    xml=z.read('docProps/app.xml').decode('utf-8','replace')
                    for tag in ('Application','AppVersion','Company','Pages','Words','Characters'):
                        m=re.search(rf'<{tag}>(.*?)</{tag}>', xml)
                        if m: meta[tag]=m.group(1)[:100]
        except Exception as e: meta["error"]=str(e)
        return meta

META = MetaReader()

# ══════════════════════════════════════════════════════════════════════════════
#  РЕКУРСИВНЫЙ АНАЛИЗ АРХИВОВ
# ══════════════════════════════════════════════════════════════════════════════
class ArchiveAnalyzer:
    MAX_DEPTH = 5
    MAX_ENTRIES = 2000

    def analyze(self, path:str, depth:int=0) -> dict:
        if depth>=self.MAX_DEPTH:
            return {"error":"Max depth reached"}
        ext=Path(path).suffix.lower()
        try:
            if ext in('.zip','.docx','.xlsx','.pptx','.jar','.apk','.odt'):
                return self._zip(path,depth)
            elif ext in('.tar','.tgz','.tar.gz','.tar.bz2','.tar.xz'):
                return self._tar(path,depth)
            elif ext in('.gz',) and not path.endswith('.tar.gz'):
                return self._gz(path,depth)
            elif ext in('.7z',):
                return self._sevenz(path,depth)
        except Exception as e:
            return {"error":str(e)}
        return {}

    def _zip(self,path,depth):
        result={"type":"ZIP","depth":depth,"entries":[],"stats":{}}
        with zipfile.ZipFile(path,'r') as z:
            infos=z.infolist()[:self.MAX_ENTRIES]
            total_comp=sum(i.compress_size for i in infos)
            total_unc =sum(i.file_size for i in infos)
            exts={}
            dangerous=[]
            nested=[]
            for info in infos:
                e=Path(info.filename).suffix.lower()
                exts[e]=exts.get(e,0)+1
                if e in VDB.dangerous_ext: dangerous.append(info.filename)
                if e in('.zip','.gz','.bz2','.7z','.tar','.rar'): nested.append(info.filename)
                result["entries"].append({
                    "name":info.filename,
                    "size":_fmt(info.file_size),
                    "compressed":_fmt(info.compress_size),
                    "is_dir":info.is_dir(),
                    "ext":e
                })
            result["stats"]={
                "total_files":len(infos),
                "compressed":_fmt(total_comp),
                "uncompressed":_fmt(total_unc),
                "ratio":f"{total_comp/total_unc*100:.1f}%" if total_unc else "—",
                "ext_summary":dict(sorted(exts.items(),key=lambda x:-x[1])[:10]),
                "dangerous_files":dangerous[:20],
                "nested_archives":nested[:10],
                "zip_bomb_risk": total_unc>1_000_000_000 or (total_comp>0 and total_unc/total_comp>200)
            }
            # Рекурсивный анализ вложенных архивов
            if nested and depth<self.MAX_DEPTH:
                result["nested"]={}
                for nname in nested[:3]:
                    try:
                        with z.open(nname) as src:
                            tmp=tempfile.NamedTemporaryFile(suffix=Path(nname).suffix,delete=False)
                            tmp.write(src.read(10*1024*1024))
                            tmp.close()
                            result["nested"][nname]=self.analyze(tmp.name,depth+1)
                            os.unlink(tmp.name)
                    except: pass
        return result

    def _tar(self,path,depth):
        result={"type":"TAR","depth":depth,"stats":{}}
        with tarfile.open(path,'r:*') as t:
            members=t.getmembers()[:self.MAX_ENTRIES]
            exts={}
            for m in members:
                e=Path(m.name).suffix.lower()
                exts[e]=exts.get(e,0)+1
            total_size=sum(m.size for m in members)
            result["stats"]={
                "total_files":len(members),
                "total_size":_fmt(total_size),
                "ext_summary":dict(sorted(exts.items(),key=lambda x:-x[1])[:10])
            }
        return result

    def _gz(self,path,depth):
        result={"type":"GZIP","depth":depth}
        with gzip.open(path,'rb') as f:
            size=sum(len(c) for c in iter(lambda:f.read(65536),b''))
        result["uncompressed_size"]=_fmt(size)
        orig_size=os.path.getsize(path)
        result["compression_ratio"]=f"{orig_size/size*100:.1f}%" if size else "—"
        return result

    def _sevenz(self,path,depth):
        result={"type":"7ZIP","depth":depth}
        try:
            r=subprocess.run(['7z','l',path],capture_output=True,timeout=15,text=True)
            lines=r.stdout.splitlines()
            count=sum(1 for l in lines if l.strip() and not l.startswith('-') and len(l)>40)
            result["approx_files"]=count
        except:
            result["error"]="7z not found"
        return result

ARCH = ArchiveAnalyzer()

# ══════════════════════════════════════════════════════════════════════════════
#  СТЕГАНОГРАФИЯ (LSB)
# ══════════════════════════════════════════════════════════════════════════════
class StegoAnalyzer:
    def analyze(self, path:str) -> dict:
        if not HAS_PIL:
            return {"error":"Требуется Pillow: pip install Pillow"}
        result={}
        try:
            img=Image.open(path).convert("RGB")
            pixels=list(img.getdata())
            w,h=img.size
            result["size"]=f"{w}×{h}"
            result["total_pixels"]=w*h

            # Плоские каналы
            r_ch=bytes(p[0] for p in pixels)
            g_ch=bytes(p[1] for p in pixels)
            b_ch=bytes(p[2] for p in pixels)

            lsb_r=CORE.lsb_randomness(r_ch)
            lsb_g=CORE.lsb_randomness(g_ch)
            lsb_b=CORE.lsb_randomness(b_ch)
            result["lsb_r"]=round(lsb_r,4)
            result["lsb_g"]=round(lsb_g,4)
            result["lsb_b"]=round(lsb_b,4)
            avg=(lsb_r+lsb_g+lsb_b)/3
            result["lsb_avg"]=round(avg,4)

            # Случайные LSB ≈ 0.5 — подозрительно (натуральные изображения: 0.45–0.55 нормально)
            # Если СЛИШКОМ близко к 0.5 и дисперсия мала → возможная стего
            dev=max(abs(lsb_r-0.5),abs(lsb_g-0.5),abs(lsb_b-0.5))
            result["suspicion_score"]=round(1.0-dev*4,2)  # 0..1

            if avg>0.48 and dev<0.03:
                result["verdict"]="⚠ Высокая вероятность LSB-стеганографии"
                result["level"]="warn"
            elif avg>0.45 and dev<0.07:
                result["verdict"]="? Возможна LSB-стеганография (проверьте вручную)"
                result["level"]="info"
            else:
                result["verdict"]="✓ LSB-паттерн в норме"
                result["level"]="ok"

            # Chi-square на LSB канале R
            lsb_bits=[b&1 for b in r_ch]
            n0=lsb_bits.count(0); n1=lsb_bits.count(1)
            total_lsb=n0+n1
            if total_lsb>0:
                expected=total_lsb/2
                chi2=((n0-expected)**2+(n1-expected)**2)/expected if expected else 0
                result["chi2_r"]=round(chi2,4)
                result["chi2_verdict"]="подозрительно (χ²<1 → почти идеальный случай)" if chi2<1 else "в норме"

        except Exception as e:
            result["error"]=str(e)
        return result

STEGO = StegoAnalyzer()

# ══════════════════════════════════════════════════════════════════════════════
#  ВОССТАНОВЛЕНИЕ ФАЙЛОВ
# ══════════════════════════════════════════════════════════════════════════════
class FileRepairer:
    HEADERS = {
        '.jpg':  b'\xff\xd8\xff\xe0\x00\x10JFIF',
        '.jpeg': b'\xff\xd8\xff\xe0\x00\x10JFIF',
        '.png':  b'\x89PNG\r\n\x1a\n',
        '.gif':  b'GIF89a',
        '.pdf':  b'%PDF-1.4\n',
        '.zip':  b'PK\x03\x04\x14\x00\x00\x00\x08\x00',
        '.gz':   b'\x1f\x8b\x08\x00\x00\x00\x00\x00',
        '.bmp':  b'BM',
        '.mp3':  b'\xff\xfb',
        '.wav':  b'RIFF',
    }
    FOOTERS = {
        '.jpg':  b'\xff\xd9',
        '.jpeg': b'\xff\xd9',
        '.png':  b'\x00\x00\x00\x00IEND\xaeB`\x82',
        '.pdf':  b'\n%%EOF\n',
        '.gif':  b'\x00;',
    }

    def attempt_repair(self, path:str, progress_cb=None) -> dict:
        result={"path":path,"actions":[],"success":False}
        ext=Path(path).suffix.lower()

        def step(msg):
            result["actions"].append(msg)
            if progress_cb: progress_cb(msg)
            time.sleep(0.1)

        step(f"Чтение файла: {os.path.basename(path)}")
        try:
            with open(path,'rb') as f: data=f.read()
        except Exception as e:
            result["error"]=str(e); return result

        original=data
        step(f"Размер: {_fmt(len(data))}, расширение: {ext}")

        # 1. Определяем реальный тип по содержимому
        detected=self._detect(data)
        if detected and detected!=ext:
            step(f"⚠ Реальный формат: {detected} (расширение: {ext})")
            result["detected_type"]=detected
        else:
            step(f"Формат соответствует расширению: {ext}")

        # 2. Починка заголовка
        use_ext=detected or ext
        if use_ext in self.HEADERS:
            expected=self.HEADERS[use_ext]
            if not data.startswith(expected):
                step(f"Заголовок повреждён — заменяю ({len(expected)} байт)")
                data=expected+data[len(expected):]
                result["header_fixed"]=True
            else:
                step("Заголовок в порядке")

        # 3. Починка хвоста
        if use_ext in self.FOOTERS:
            expected=self.FOOTERS[use_ext]
            if not data.endswith(expected):
                step(f"Хвост отсутствует — добавляю {len(expected)} байт")
                data=data+expected
                result["footer_fixed"]=True
            else:
                step("Хвост в порядке")

        # 4. ZIP: попытка найти Local File Header если начало обрезано
        if use_ext in('.zip','.docx','.xlsx','.pptx','.jar','.apk'):
            pk_pos=data.find(b'PK\x03\x04')
            if pk_pos>0:
                step(f"ZIP: локальный заголовок найден на смещении {pk_pos} — обрезаю префикс")
                data=data[pk_pos:]
                result["zip_trimmed"]=True

        # 5. GZIP: попытка найти magic
        if use_ext=='.gz':
            gz_pos=data.find(b'\x1f\x8b')
            if gz_pos>0:
                step(f"GZIP: magic найден на смещении {gz_pos}")
                data=data[gz_pos:]

        # 6. Сохраняем если что-то изменилось
        if data!=original:
            backup=path+".sonar_bak"
            try:
                shutil.copy2(path,backup)
                step(f"Резервная копия: {os.path.basename(backup)}")
                with open(path,'wb') as f: f.write(data)
                result["saved"]=True
                result["success"]=True
                step(f"✓ Файл восстановлен ({_fmt(len(data))})")
            except Exception as e:
                step(f"✗ Не удалось сохранить: {e}")
                result["error"]=str(e)
        else:
            step("Изменений не найдено — файл уже в порядке или восстановить невозможно")
            result["success"]=True
            result["no_changes"]=True

        return result

    def _detect(self,data):
        SIGS={b'\x89PNG\r\n\x1a\n':'.png',b'\xff\xd8\xff':'.jpg',
              b'%PDF':'.pdf',b'PK\x03\x04':'.zip',b'\x1f\x8b':'.gz',
              b'GIF8':'.gif',b'BM':'.bmp',b'RIFF':'.wav',b'ID3':'.mp3',
              b'\x7fELF':'.elf',b'MZ':'.exe'}
        for sig,ext in SIGS.items():
            if data[:len(sig)]==sig: return ext
        return None

REPAIRER = FileRepairer()

# ══════════════════════════════════════════════════════════════════════════════
#  АНАЛИЗ УГРОЗ (расширенный)
# ══════════════════════════════════════════════════════════════════════════════
_MALWARE_NAME_RE=re.compile(
    r'(invoice|free.?crack|keygen|patch|serial|activat|hack|trojan'
    r'|ransomware|virus|malware|payload|exploit|dropper|loader|stager'
    r'|bypass|inject|shellcode|rootkit|backdoor|crypter|obfuscat)',re.IGNORECASE)
_DOUBLE_EXT_RE=re.compile(
    r'\.(pdf|doc|docx|jpg|png|mp3|mp4|txt)\.(exe|bat|cmd|vbs|js|ps1|scr|pif|com)$',re.IGNORECASE)

def threat_scan(path:str,entropy:float,null_ratio:float,first64k:bytes) -> dict:
    reasons=[]; level="clean"
    _lv={"clean":0,"suspicious":1,"danger":2}
    def _up(l): nonlocal level; level=l if _lv[l]>_lv[level] else level

    fname=os.path.basename(path); ext=Path(path).suffix.lower()

    # 1. База сигнатур
    hits=VDB.scan(path,first64k)
    for h in hits:
        if h["severity"]=="danger":
            reasons.append(f"🚨 [{h['type'].upper()}] {h['name']}"); _up("danger")
        elif h["severity"]=="warn":
            reasons.append(f"⚠ [{h['type'].upper()}] {h['name']}"); _up("suspicious")
        else:
            reasons.append(f"ℹ {h['name']}")

    # 2. Двойное расширение
    if _DOUBLE_EXT_RE.search(fname):
        reasons.append(f"🚨 Двойное расширение: «{fname}»"); _up("danger")

    # 3. Имя
    if _MALWARE_NAME_RE.search(fname):
        reasons.append("⚠ Подозрительное имя файла"); _up("suspicious")

    # 4. Энтропия EXE
    if ext in('.exe','.dll','.scr','.sys','.com') and entropy>7.2:
        reasons.append(f"⚠ EXE высокая энтропия ({entropy:.2f}) — возможен пакер"); _up("suspicious")

    # 5. Скрипт с обфускацией
    if ext in('.js','.vbs','.ps1','.bat','.cmd') and entropy>5.5:
        reasons.append(f"⚠ Скрипт с высокой энтропией ({entropy:.2f})"); _up("suspicious")

    # 6. ZIP-бомба
    if ext in('.zip','.docx','.xlsx','.pptx','.jar','.apk'):
        try:
            with zipfile.ZipFile(path,'r') as z:
                comp=sum(i.compress_size for i in z.infolist())
                unc =sum(i.file_size for i in z.infolist())
                if unc>1_000_000_000:
                    reasons.append(f"🚨 ZIP-бомба: {unc//1_000_000} МБ распакованных"); _up("danger")
                elif comp>0 and unc/comp>200:
                    reasons.append(f"⚠ Подозрительное сжатие ×{unc/comp:.0f}"); _up("suspicious")
                exes=[n for n in z.namelist() if Path(n).suffix.lower() in VDB.dangerous_ext]
                if exes:
                    reasons.append(f"⚠ Исполняемые в архиве: {', '.join(exes[:3])}"
                                   +(f" +{len(exes)-3}" if len(exes)>3 else "")); _up("suspicious")
        except: pass

    # 7. PDF-эксплойты
    if ext=='.pdf':
        if b'/JavaScript' in first64k or b'/JS' in first64k:
            reasons.append("⚠ PDF /JavaScript"); _up("suspicious")
        if b'/Launch' in first64k:
            reasons.append("🚨 PDF /Launch (известный эксплойт)"); _up("danger")

    # 8. Много нулей в EXE
    if ext in('.exe','.dll') and null_ratio>0.6:
        reasons.append(f"⚠ {null_ratio*100:.0f}% нулевых байт в EXE"); _up("suspicious")

    return {"level":level,"reasons":reasons,"hits":hits}

# ══════════════════════════════════════════════════════════════════════════════
#  АНАЛИЗ ПРОЦЕССОВ И АВТОЗАГРУЗКИ
# ══════════════════════════════════════════════════════════════════════════════
class ProcessScanner:
    SUSPICIOUS_NAMES=re.compile(
        r'(miner|cryptominer|xmrig|monero|coinhive|svchost32|svch0st'
        r'|wscript|cscript|powershell|cmd|regsvr32|rundll|mshta|certutil'
        r'|bitsadmin|wmic|cmstp)',re.IGNORECASE)

    def scan_processes(self) -> list:
        if not HAS_PSUTIL: return [{"error":"psutil not available"}]
        results=[]
        try:
            for proc in psutil.process_iter(['pid','name','exe','cpu_percent','memory_info','status']):
                try:
                    info=proc.info
                    suspicious=bool(self.SUSPICIOUS_NAMES.search(info.get('name','') or ''))
                    mem=info['memory_info'].rss if info.get('memory_info') else 0
                    results.append({
                        "pid": info['pid'],
                        "name": info.get('name','?'),
                        "exe": info.get('exe','?') or '?',
                        "cpu": info.get('cpu_percent',0),
                        "mem": _fmt(mem),
                        "status": info.get('status','?'),
                        "suspicious": suspicious
                    })
                except: pass
        except Exception as e:
            results.append({"error":str(e)})
        return sorted(results,key=lambda x:x.get('suspicious',False),reverse=True)

    def scan_autorun(self) -> list:
        results=[]
        sys_name=platform.system()
        if sys_name=="Windows":
            results+=self._win_autorun()
        elif sys_name=="Linux":
            results+=self._linux_autorun()
        elif sys_name=="Darwin":
            results+=self._mac_autorun()
        return results

    def _win_autorun(self):
        items=[]
        keys=["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"]
        for key in keys:
            try:
                r=subprocess.run(["reg","query",key],capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    if 'REG_' in line:
                        parts=line.strip().split(None,2)
                        if len(parts)>=3:
                            name,_,val=parts[0],parts[1],parts[2]
                            suspicious=bool(self.SUSPICIOUS_NAMES.search(val))
                            items.append({"location":key,"name":name,"value":val[:100],"suspicious":suspicious})
            except: pass
        return items

    def _linux_autorun(self):
        items=[]
        paths=[Path('/etc/init.d'),Path('/etc/rc.local'),Path.home()/'.config/autostart',
               Path('/etc/xdg/autostart')]
        for p in paths:
            try:
                if p.is_file():
                    items.append({"location":str(p),"name":p.name,"value":"script","suspicious":False})
                elif p.is_dir():
                    for f in p.iterdir():
                        if f.is_file():
                            suspicious=bool(self.SUSPICIOUS_NAMES.search(f.name))
                            items.append({"location":str(p),"name":f.name,
                                         "value":str(f),"suspicious":suspicious})
            except: pass
        # systemd
        for svc_dir in (Path('/etc/systemd/system'),Path('/lib/systemd/system')):
            try:
                if svc_dir.exists():
                    for f in list(svc_dir.glob('*.service'))[:20]:
                        items.append({"location":str(svc_dir),"name":f.name,"value":str(f),"suspicious":False})
            except: pass
        return items

    def _mac_autorun(self):
        items=[]
        for d in (Path.home()/'Library/LaunchAgents',Path('/Library/LaunchAgents'),
                  Path('/Library/LaunchDaemons')):
            try:
                if d.exists():
                    for f in d.glob('*.plist'):
                        items.append({"location":str(d),"name":f.name,"value":str(f),"suspicious":False})
            except: pass
        return items

PROC_SCANNER = ProcessScanner()

# ══════════════════════════════════════════════════════════════════════════════
#  ТЕСТЫ УСТРОЙСТВ
# ══════════════════════════════════════════════════════════════════════════════
class DeviceTester:

    # ── Батарея ───────────────────────────────────────────────────────────
    def battery(self) -> dict:
        r={"available":False}
        if HAS_PSUTIL:
            try:
                b=psutil.sensors_battery()
                if b:
                    r={"available":True,"percent":round(b.percent,1),
                       "plugged":b.power_plugged,
                       "time_left":str(timedelta(seconds=int(b.secsleft))) if b.secsleft>0 else "∞"}
            except: pass
        if not r["available"] and platform.system()=="Linux":
            try:
                bp=Path("/sys/class/power_supply/BAT0")
                if bp.exists():
                    cap=int((bp/"capacity").read_text().strip())
                    status=(bp/"status").read_text().strip()
                    r={"available":True,"percent":cap,"plugged":status=="Charging","time_left":"?"}
                    try:
                        cyc=int((bp/"cycle_count").read_text().strip())
                        r["cycles"]=cyc
                    except: pass
                    try:
                        full=int((bp/"energy_full").read_text().strip())
                        design=int((bp/"energy_full_design").read_text().strip())
                        r["health"]=round(full/design*100,1) if design else None
                    except: pass
            except: pass
        if platform.system()=="Windows" and not r["available"]:
            try:
                out=subprocess.check_output(
                    ["powershell","-Command",
                     "Get-WmiObject Win32_Battery | Select-Object EstimatedChargeRemaining,BatteryStatus,DesignCapacity,FullChargeCapacity"],
                    timeout=8,text=True)
                for line in out.splitlines():
                    if "EstimatedChargeRemaining" in line:
                        pct=re.search(r'\d+',line.split(':')[-1])
                        if pct: r={"available":True,"percent":int(pct.group()),"plugged":False,"time_left":"?"}
            except: pass
        return r

    # ── Сеть / Wi-Fi ──────────────────────────────────────────────────────
    def network_test(self, progress_cb=None) -> dict:
        r={"ping_ms":None,"download_mbps":None,"upload_mbps":None,"packet_loss":None,"details":[]}
        def step(msg):
            r["details"].append(msg)
            if progress_cb: progress_cb(msg)

        step("Проверка подключения к интернету…")
        # Ping
        for host in ("8.8.8.8","1.1.1.1","ya.ru"):
            try:
                cmd=["ping","-c","4",host] if platform.system()!="Windows" else ["ping","-n","4",host]
                pr=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
                out=pr.stdout
                # Парсим avg
                m=re.search(r'avg[/ ]+\S+?(\d+\.\d+)',out) or re.search(r'Average\s*=\s*(\d+)',out)
                if m:
                    r["ping_ms"]=float(m.group(1)); step(f"Ping {host}: {r['ping_ms']} ms"); break
                # Потери
                ml=re.search(r'(\d+)%\s+packet loss',out) or re.search(r'(\d+)%\s+loss',out)
                if ml: r["packet_loss"]=int(ml.group(1))
            except: pass

        step("Тест скачивания (HTTP)…")
        try:
            import urllib.request, time as _t
            url="http://speedtest.tele2.net/1MB.zip"
            start=_t.time()
            with urllib.request.urlopen(url,timeout=10) as resp:
                data_len=len(resp.read(1024*1024))
            elapsed=_t.time()-start
            if elapsed>0:
                r["download_mbps"]=round(data_len*8/elapsed/1_000_000,2)
                step(f"Скачивание: {r['download_mbps']} Мбит/с")
        except Exception as e:
            step(f"Тест скачивания недоступен: {e}")

        # Интерфейсы
        if HAS_PSUTIL:
            try:
                stats=psutil.net_if_stats()
                addrs=psutil.net_if_addrs()
                for iface,stat in stats.items():
                    addr_list=addrs.get(iface,[])
                    ips=[a.address for a in addr_list if a.family==socket.AF_INET]
                    if stat.isup and ips:
                        step(f"Интерфейс: {iface} — {ips[0]} ({stat.speed} Мбит/с)")
            except: pass
        return r

    # ── USB ───────────────────────────────────────────────────────────────
    def usb_info(self) -> list:
        devices=[]
        if platform.system()=="Linux":
            try:
                out=subprocess.check_output(["lsusb"],timeout=5,text=True)
                for line in out.splitlines():
                    m=re.match(r'Bus (\d+) Device (\d+): ID (\S+) (.*)',line)
                    if m:
                        devices.append({"bus":m.group(1),"dev":m.group(2),
                                        "id":m.group(3),"name":m.group(4)[:60]})
            except: pass
        elif platform.system()=="Windows":
            try:
                out=subprocess.check_output(
                    ["powershell","-Command",
                     "Get-PnpDevice -Class USB | Select-Object -ExpandProperty FriendlyName"],
                    timeout=8,text=True)
                for line in out.splitlines():
                    if line.strip():
                        devices.append({"name":line.strip()[:80]})
            except: pass
        elif platform.system()=="Darwin":
            try:
                out=subprocess.check_output(
                    ["system_profiler","SPUSBDataType","-detailLevel","mini"],
                    timeout=10,text=True)
                for line in out.splitlines():
                    if 'Product ID' in line or line.strip().startswith('USB'):
                        devices.append({"name":line.strip()[:80]})
            except: pass
        return devices

    # ── Bluetooth ─────────────────────────────────────────────────────────
    def bluetooth_scan(self, progress_cb=None) -> dict:
        r={"devices":[],"details":[]}
        def step(msg):
            r["details"].append(msg); progress_cb(msg) if progress_cb else None

        step("Сканирование Bluetooth…")
        if platform.system()=="Linux":
            try:
                out=subprocess.check_output(["bluetoothctl","devices"],timeout=5,text=True)
                for line in out.splitlines():
                    m=re.match(r'Device (\S+) (.*)',line)
                    if m: r["devices"].append({"mac":m.group(1),"name":m.group(2)})
                step(f"Найдено сохранённых устройств: {len(r['devices'])}")
                # Сканируем 5 сек
                proc=subprocess.Popen(["bluetoothctl","scan","on"],
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                time.sleep(5); proc.terminate()
                step("Сканирование завершено")
            except Exception as e: step(f"bluetoothctl: {e}")
        elif platform.system()=="Windows":
            try:
                out=subprocess.check_output(
                    ["powershell","-Command",
                     "Get-PnpDevice -Class Bluetooth | Select-Object FriendlyName,Status"],
                    timeout=8,text=True)
                for line in out.splitlines():
                    if line.strip() and 'FriendlyName' not in line and '---' not in line:
                        r["devices"].append({"name":line.strip()[:60]})
                step(f"Найдено BT-устройств: {len(r['devices'])}")
            except Exception as e: step(f"PowerShell BT: {e}")
        else:
            step("Bluetooth-сканирование поддерживается на Linux/Windows")
        return r

    # ── Динамики ──────────────────────────────────────────────────────────
    def speaker_test(self, freq_hz:int=1000, duration:float=1.0) -> dict:
        r={"freq":freq_hz,"duration":duration,"status":"?"}
        try:
            rate=44100
            samples=int(rate*duration)
            data=bytearray(samples*2)
            for i in range(samples):
                v=int(32767*math.sin(2*math.pi*freq_hz*i/rate))
                struct.pack_into('<h',data,i*2,v)
            # Пишем WAV во временный файл и играем
            tmp=tempfile.NamedTemporaryFile(suffix='.wav',delete=False)
            with wave.open(tmp.name,'wb') as wf:
                wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(rate)
                wf.writeframes(bytes(data))
            tmp.close()
            if platform.system()=="Linux":
                ret=subprocess.run(["aplay","-q",tmp.name],timeout=duration+2).returncode
                r["status"]="ok" if ret==0 else "aplay not found"
            elif platform.system()=="Windows":
                import winsound
                winsound.PlaySound(tmp.name,winsound.SND_FILENAME|winsound.SND_ASYNC)
                time.sleep(duration+0.2); r["status"]="ok"
            elif platform.system()=="Darwin":
                subprocess.run(["afplay",tmp.name],timeout=duration+2)
                r["status"]="ok"
            os.unlink(tmp.name)
        except Exception as e:
            r["status"]=str(e)
        return r

    # ── Дисплей ───────────────────────────────────────────────────────────
    def display_test(self, root:tk.Tk):
        """Открывает окна тестирования дисплея."""
        _DisplayTestWindow(root)

DEV = DeviceTester()

# ══════════════════════════════════════════════════════════════════════════════
#  REAL-TIME МОНИТОРИНГ
# ══════════════════════════════════════════════════════════════════════════════
class FileMonitor:
    def __init__(self, callback):
        self._cb=callback
        self._watching={}
        self._active=False
        self._thread=None

    def add(self,path:str):
        try:
            st=os.stat(path)
            self._watching[path]={"mtime":st.st_mtime,"size":st.st_size}
        except: pass

    def remove(self,path:str):
        self._watching.pop(path,None)

    def start(self):
        if self._active: return
        self._active=True
        self._thread=threading.Thread(target=self._run,daemon=True)
        self._thread.start()

    def stop(self):
        self._active=False

    def _run(self):
        while self._active:
            for path,old in list(self._watching.items()):
                try:
                    st=os.stat(path)
                    if st.st_mtime!=old["mtime"] or st.st_size!=old["size"]:
                        self._cb(path,"modified",old["size"],st.st_size)
                        self._watching[path]={"mtime":st.st_mtime,"size":st.st_size}
                except FileNotFoundError:
                    self._cb(path,"deleted",old["size"],0)
                    self._watching.pop(path,None)
                except: pass
            time.sleep(1.0)

# ══════════════════════════════════════════════════════════════════════════════
#  ПЛАНИРОВЩИК
# ══════════════════════════════════════════════════════════════════════════════
class Scheduler:
    def __init__(self,scan_callback):
        self._cb=scan_callback
        self._jobs=[]  # {"label":str,"interval_min":int,"next":datetime,"paths":[]}
        self._active=False
        self._thread=None

    def add_job(self,label:str,interval_min:int,paths:list):
        self._jobs.append({"label":label,"interval_min":interval_min,
                           "next":datetime.now()+timedelta(minutes=interval_min),"paths":paths})

    def remove_job(self,label:str):
        self._jobs=[j for j in self._jobs if j["label"]!=label]

    def start(self):
        if self._active: return
        self._active=True
        self._thread=threading.Thread(target=self._run,daemon=True)
        self._thread.start()

    def stop(self): self._active=False

    def _run(self):
        while self._active:
            now=datetime.now()
            for job in self._jobs:
                if now>=job["next"]:
                    threading.Thread(target=self._cb,args=(job["paths"],job["label"]),daemon=True).start()
                    job["next"]=now+timedelta(minutes=job["interval_min"])
            time.sleep(30)

# ══════════════════════════════════════════════════════════════════════════════
#  HTML-ЭКСПОРТ
# ══════════════════════════════════════════════════════════════════════════════
def export_html(results:list, log_entries:list, path:str):
    hist_labels=list(range(256))
    # Берём первый файл с гистограммой для демо
    hist_data=[0]*256
    for r in results:
        if r.get("deep") and r["deep"].get("histogram"):
            hist_data=r["deep"]["histogram"]; break

    rows=""
    for r in results:
        status=r.get("status","?")
        color={"ok":"#27ae60","warn":"#f39c12","error":"#e74c3c"}.get(status,"#888")
        icon={"ok":"✓","warn":"⚠","error":"✗"}.get(status,"?")
        deep=r.get("deep",{})
        threat=deep.get("threat",{})
        t_col={"clean":"#27ae60","suspicious":"#f39c12","danger":"#e74c3c"}.get(threat.get("level","clean"),"#888")
        t_txt=threat.get("level","—")
        rows+=f"""
        <tr>
          <td style="color:{color};font-weight:bold">{icon}</td>
          <td title="{r['path']}">{r['name']}</td>
          <td>{r.get('type','?')}</td>
          <td style="text-align:right">{_fmt(r.get('size',0))}</td>
          <td>{deep.get('crc32','—')}</td>
          <td>{deep.get('entropy','—')}</td>
          <td style="color:{t_col};font-weight:bold">{t_txt}</td>
          <td>{'; '.join(r.get('issues',[]))[:80] or '—'}</td>
        </tr>"""

    entropy_bars=""
    for r in results:
        deep=r.get("deep",{})
        ent=deep.get("entropy","")
        if ent != "":
            entropy_bars+=f"'{r['name'][:20]}': {ent},"

    html=f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sonar Report — {_dt()}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:"Segoe UI",Arial,sans-serif;background:#0D1117;color:#C9D1D9;font-size:13px}}
  .header{{background:linear-gradient(135deg,#1F6FEB,#0D419D);padding:24px 32px;}}
  .header h1{{font-size:28px;color:#fff;letter-spacing:2px}}
  .header p{{color:#8B949E;margin-top:4px}}
  .stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:20px 32px;}}
  .stat-card{{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px;text-align:center}}
  .stat-card .val{{font-size:32px;font-weight:700;color:#58A6FF}}
  .stat-card .lbl{{color:#8B949E;font-size:11px;margin-top:4px;text-transform:uppercase}}
  .section{{padding:16px 32px 0}}
  .section h2{{font-size:15px;color:#58A6FF;border-bottom:1px solid #30363D;padding-bottom:8px;margin-bottom:12px}}
  table{{width:100%;border-collapse:collapse;background:#161B22;border-radius:8px;overflow:hidden}}
  th{{background:#21262D;color:#8B949E;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase}}
  td{{padding:7px 12px;border-bottom:1px solid #21262D;font-family:Consolas,monospace;font-size:12px}}
  tr:hover{{background:#21262D}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:20px 32px;}}
  .chart-card{{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px}}
  .chart-card h3{{color:#8B949E;font-size:12px;margin-bottom:12px;text-transform:uppercase}}
  .footer{{text-align:center;padding:24px;color:#8B949E;font-size:11px;border-top:1px solid #21262D;margin-top:20px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
  .badge-ok{{background:#0D4429;color:#3FB950}}
  .badge-warn{{background:#3D2B00;color:#D29922}}
  .badge-danger{{background:#3D0000;color:#F85149}}
</style>
</head>
<body>
<div class="header">
  <h1>🔊 SONAR</h1>
  <p>Отчёт диагностики файлов · {_dt()} · C-ядро: {"активно" if CORE.available else "Python fallback"} · Сигнатур: {len(VDB.signatures)}</p>
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="val">{len(results)}</div><div class="lbl">Файлов</div></div>
  <div class="stat-card"><div class="val" style="color:#3FB950">{sum(1 for r in results if r.get('status')=='ok')}</div><div class="lbl">Исправных</div></div>
  <div class="stat-card"><div class="val" style="color:#D29922">{sum(1 for r in results if r.get('status')=='warn')}</div><div class="lbl">Предупреждений</div></div>
  <div class="stat-card"><div class="val" style="color:#F85149">{sum(1 for r in results if r.get('status')=='error')}</div><div class="lbl">Повреждённых</div></div>
</div>

<div class="section"><h2>📋 Результаты проверки</h2>
<table>
<thead><tr><th></th><th>Файл</th><th>Тип</th><th>Размер</th><th>CRC-32</th><th>Энтропия</th><th>Угроза</th><th>Детали</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>

<div class="charts">
  <div class="chart-card"><h3>Энтропия файлов (бит/байт)</h3>
    <canvas id="entropyChart" height="200"></canvas></div>
  <div class="chart-card"><h3>Байтовая гистограмма (первый файл с анализом)</h3>
    <canvas id="histChart" height="200"></canvas></div>
</div>

<div class="section" style="margin-bottom:20px"><h2>📝 Журнал сканирования</h2>
<table><thead><tr><th>Время</th><th>Уровень</th><th>Сообщение</th></tr></thead><tbody>
{"".join(f'<tr><td>{ts}</td><td><span class="badge badge-{"ok" if lvl=="ok" else "warn" if lvl=="warn" else "danger" if lvl=="err" or lvl=="threat" else "ok"}">{lvl.upper()}</span></td><td>{msg}</td></tr>' for ts,lvl,msg in log_entries[-50:])}
</tbody></table></div>

<div class="footer">Sonar v3.0 · Сгенерировано {_dt()} · <a href="https://github.com" style="color:#58A6FF">GitHub</a></div>

<script>
const entropyData = {{{entropy_bars}}};
const labels=Object.keys(entropyData); const vals=Object.values(entropyData);
const ctx1=document.getElementById('entropyChart').getContext('2d');
new Chart(ctx1,{{type:'bar',data:{{labels,datasets:[{{label:'Энтропия',data:vals,
  backgroundColor:vals.map(v=>v>7?'#F85149':v>6?'#D29922':'#3FB950'),borderRadius:4}}]}},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{max:8,grid:{{color:'#30363D'}},ticks:{{color:'#8B949E'}}}},x:{{grid:{{color:'#30363D'}},ticks:{{color:'#8B949E',maxRotation:45}}}}}}}}}});

const hist=HIST_DATA_PLACEHOLDER;
const ctx2=document.getElementById('histChart').getContext('2d');
new Chart(ctx2,{{type:'bar',data:{{labels:Array.from({{length:64}},(_,i)=>'0x'+i.toString(16).padStart(2,'0')),
  datasets:[{{label:'Частота',data:hist,backgroundColor:'#1F6FEB',borderRadius:2}}]}},
  options:{{plugins:{{legend:{{display:false}}}},scales:{{y:{{grid:{{color:'#30363D'}},ticks:{{color:'#8B949E'}}}},x:{{grid:{{color:'#30363D'}},ticks:{{color:'#8B949E',maxRotation:90,font:{{size:9}}}}}}}}}}}}
}});
</script>
</body></html>"""
    html = html.replace('HIST_DATA_PLACEHOLDER', __import__('json').dumps(hist_data[:64]))
    with open(path,'w',encoding='utf-8') as f: f.write(html)

# ══════════════════════════════════════════════════════════════════════════════
#  ОКНА ДОПОЛНИТЕЛЬНЫХ ФУНКЦИЙ
# ══════════════════════════════════════════════════════════════════════════════

class _DiffWindow(tk.Toplevel):
    """Построчный diff двух текстовых файлов."""
    def __init__(self,parent,path1):
        super().__init__(parent)
        self.title(f"Сравнение — {os.path.basename(path1)}")
        self.geometry("900x620"); self.configure(bg="#1E1E1E")

        # Тулбар
        tb=tk.Frame(self,bg="#2D2D2D",height=32); tb.pack(fill="x"); tb.pack_propagate(False)
        tk.Button(tb,text="📂 Открыть второй файл…",command=self._open_second,
                  bg="#2D2D2D",fg="#D4D4D4",relief="flat",font=("Segoe UI",8),cursor="hand2"
                  ).pack(side="left",padx=6,pady=4)
        self._path1=path1; self._path2=None

        # Легенда
        leg=tk.Frame(self,bg="#1E1E1E"); leg.pack(fill="x",padx=8,pady=4)
        for col,lbl in (("#1e4620","+ Добавлено"),("#4b1113","− Удалено"),("#1a3a5c","  Изменено")):
            tk.Label(leg,text=f"  {lbl}  ",bg=col,fg="white",font=("Segoe UI",8)).pack(side="left",padx=2)
        tk.Label(leg,text=f"  Файл 1: {os.path.basename(path1)}  ",
                 bg="#1E1E1E",fg="#888",font=("Segoe UI",8)).pack(side="right")

        # Текстовый виджет
        frame=tk.Frame(self,bg="#1E1E1E"); frame.pack(fill="both",expand=True,padx=6,pady=6)
        xsb=ttk.Scrollbar(frame,orient="horizontal"); ysb=ttk.Scrollbar(frame,orient="vertical")
        self._txt=tk.Text(frame,font=("Consolas",9),bg="#1E1E1E",fg="#D4D4D4",
                          wrap="none",state="disabled",
                          xscrollcommand=xsb.set,yscrollcommand=ysb.set)
        xsb.configure(command=self._txt.xview); ysb.configure(command=self._txt.yview)
        xsb.pack(side="bottom",fill="x"); ysb.pack(side="right",fill="y")
        self._txt.pack(fill="both",expand=True)
        self._txt.tag_configure("add",  background="#1e4620",foreground="#95d89f")
        self._txt.tag_configure("del",  background="#4b1113",foreground="#f28b82")
        self._txt.tag_configure("chg",  background="#1a3a5c",foreground="#89c4f4")
        self._txt.tag_configure("eq",   foreground="#888888")
        self._txt.tag_configure("hdr",  foreground="#569CD6",font=("Consolas",9,"bold"))
        self._txt.tag_configure("lnum", foreground="#555",font=("Consolas",9))

        # Статусбар
        self._status=tk.Label(self,text="Откройте второй файл для сравнения",
                              bg="#007ACC",fg="white",font=("Segoe UI",8),anchor="w")
        self._status.pack(fill="x",side="bottom")

    def _open_second(self):
        p=filedialog.askopenfilename(title="Выберите второй файл для сравнения")
        if not p: return
        self._path2=p
        self._run_diff()

    def _run_diff(self):
        try:
            enc_list=["utf-8","cp1251","latin-1"]
            def _read(p):
                for enc in enc_list:
                    try:
                        with open(p,'r',encoding=enc) as f: return f.readlines()
                    except: pass
                with open(p,'rb') as f: return [l.decode('latin-1') for l in f.readlines()]

            lines1=_read(self._path1); lines2=_read(self._path2)
            differ=difflib.unified_diff(lines1,lines2,
                fromfile=os.path.basename(self._path1),
                tofile=os.path.basename(self._path2),lineterm='')
            diff_lines=list(differ)

            self._txt.configure(state="normal"); self._txt.delete("1.0","end")
            add_c=del_c=chg_c=0
            lnum=0
            for line in diff_lines:
                lnum+=1
                ln=f"{lnum:>5}  "
                if line.startswith("+++") or line.startswith("---"):
                    self._txt.insert("end",ln,"lnum"); self._txt.insert("end",line+"\n","hdr")
                elif line.startswith("@@"):
                    self._txt.insert("end","\n"); self._txt.insert("end",ln,"lnum")
                    self._txt.insert("end",line+"\n","hdr")
                elif line.startswith("+"):
                    add_c+=1; self._txt.insert("end",ln,"lnum"); self._txt.insert("end",line+"\n","add")
                elif line.startswith("-"):
                    del_c+=1; self._txt.insert("end",ln,"lnum"); self._txt.insert("end",line+"\n","del")
                else:
                    self._txt.insert("end",ln,"lnum"); self._txt.insert("end",line+"\n","eq")

            self._txt.configure(state="disabled")
            self._status.configure(
                text=f"  Добавлено: +{add_c}  Удалено: -{del_c}  "
                     f"Строк файл 1: {len(lines1)}  файл 2: {len(lines2)}")
        except Exception as e:
            messagebox.showerror("Ошибка diff",str(e))


class _RepairWindow(tk.Toplevel):
    """Окно восстановления файла."""
    def __init__(self,parent,path):
        super().__init__(parent)
        self.title(f"Восстановление — {os.path.basename(path)}")
        self.geometry("560x420"); self.configure(bg="#1E1E1E"); self.resizable(False,False)
        self.grab_set()

        hdr=tk.Frame(self,bg="#264F78",height=40); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text=f"  🔧 Восстановление файла: {os.path.basename(path)}",
                 bg="#264F78",fg="white",font=("Segoe UI",10,"bold")).pack(side="left",padx=8,pady=8)

        self._prog=ttk.Progressbar(self,mode="indeterminate",length=540)
        self._prog.pack(padx=10,pady=(10,4))

        self._txt=tk.Text(self,font=("Consolas",8),bg="#0D0D0D",fg="#D4D4D4",
                          state="disabled",relief="flat",padx=6,pady=4)
        self._txt.pack(fill="both",expand=True,padx=6,pady=4)
        self._txt.tag_configure("ok",  foreground="#4EC94E")
        self._txt.tag_configure("err", foreground="#FF6666")
        self._txt.tag_configure("info",foreground="#569CD6")

        self._btn=tk.Button(self,text="Закрыть",command=self.destroy,
                            bg="#264F78",fg="white",font=("Segoe UI",9),relief="flat",state="disabled")
        self._btn.pack(pady=6)

        self._prog.start(10)
        threading.Thread(target=self._run,args=(path,),daemon=True).start()

    def _log(self,msg,tag="info"):
        self._txt.configure(state="normal")
        self._txt.insert("end",f"  {msg}\n",tag)
        self._txt.see("end"); self._txt.configure(state="disabled")

    def _run(self,path):
        def cb(msg): self.after(0,lambda:self._log(msg))
        result=REPAIRER.attempt_repair(path,progress_cb=cb)
        self.after(0,self._done,result)

    def _done(self,result):
        self._prog.stop()
        if result.get("success"):
            if result.get("no_changes"):
                self._log("✓ Файл в порядке или восстановить невозможно","ok")
            else:
                self._log("✓ Восстановление успешно!","ok")
        else:
            self._log(f"✗ Не удалось восстановить: {result.get('error','')}","err")
        self._btn.configure(state="normal")


class _ArchiveViewWindow(tk.Toplevel):
    """Рекурсивный просмотр архива."""
    def __init__(self,parent,path):
        super().__init__(parent)
        self.title(f"Структура архива — {os.path.basename(path)}")
        self.geometry("700x500"); self.configure(bg="#1E1E1E")

        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text=f"  📦 {os.path.basename(path)}",
                 bg="#264F78",fg="white",font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)

        self._tree=ttk.Treeview(self,show="tree headings",
                                 columns=("size","type","flag"))
        self._tree.heading("#0",  text="Имя")
        self._tree.heading("size",text="Размер",anchor="e")
        self._tree.heading("type",text="Тип",   anchor="center")
        self._tree.heading("flag",text="",       anchor="center")
        self._tree.column("#0",  width=340)
        self._tree.column("size",width=90, anchor="e")
        self._tree.column("type",width=80, anchor="center")
        self._tree.column("flag",width=60, anchor="center")
        self._tree.tag_configure("danger",foreground="#FF6666")
        self._tree.tag_configure("warn",  foreground="#FFCC44")
        self._tree.tag_configure("dir",   foreground="#569CD6")
        vsb=ttk.Scrollbar(self,command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); self._tree.pack(fill="both",expand=True)

        self._status=tk.Label(self,text="Анализируется…",bg="#007ACC",fg="white",
                              font=("Segoe UI",8),anchor="w")
        self._status.pack(fill="x",side="bottom")

        threading.Thread(target=self._analyze,args=(path,),daemon=True).start()

    def _analyze(self,path):
        result=ARCH.analyze(path)
        self.after(0,self._populate,result,path)

    def _populate(self,result,path):
        stats=result.get("stats",{})
        root_id=self._tree.insert("","end",text=f"📦 {os.path.basename(path)}",
                                   values=(stats.get("uncompressed","?"),"ZIP",""),open=True)
        entries=result.get("entries",[])
        for e in entries[:500]:
            flag="🚨" if Path(e["name"]).suffix.lower() in VDB.dangerous_ext else \
                 "⚠" if Path(e["name"]).suffix.lower() in VDB.suspicious_ext else ""
            tag="danger" if flag=="🚨" else "warn" if flag=="⚠" else "dir" if e.get("is_dir") else ""
            icon="📁" if e.get("is_dir") else "📄"
            self._tree.insert(root_id,"end",text=f"{icon} {e['name']}",
                               values=(e["size"],e["ext"],flag),tags=(tag,))
        if len(entries)>500:
            self._tree.insert(root_id,"end",text=f"… ещё {len(entries)-500} файлов")
        # Вложенные
        nested=result.get("nested",{})
        if nested:
            nid=self._tree.insert(root_id,"end",text="🔍 Вложенные архивы",open=True)
            for name,sub in nested.items():
                sub_stats=sub.get("stats",{})
                self._tree.insert(nid,"end",text=f"📦 {name}",
                    values=(_fmt(0),"nested",""))
        danger=stats.get("dangerous_files",[])
        if danger:
            did=self._tree.insert("","end",text=f"🚨 Опасные файлы ({len(danger)})",
                                   open=True,tags=("danger",))
            for f in danger:
                self._tree.insert(did,"end",text=f"  ⚠ {f}",tags=("danger",))
        self._status.configure(text=f"  Файлов: {stats.get('total_files','?')}  "
                                f"Сжато: {stats.get('compressed','?')}  "
                                f"Распак: {stats.get('uncompressed','?')}  "
                                f"Коэфф.: {stats.get('ratio','?')}"
                                +("  ⚠ ZIP-БОМБА!" if stats.get("zip_bomb_risk") else ""))


class _DisplayTestWindow(tk.Toplevel):
    """Тест дисплея: мёртвые пиксели, цветопередача."""
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Тест дисплея")
        self.attributes("-fullscreen",True)
        self.configure(bg="black")
        self._colors=["#FF0000","#00FF00","#0000FF","#FFFFFF","#000000",
                      "#FFFF00","#FF00FF","#00FFFF","#808080"]
        self._idx=0
        self._canvas=tk.Canvas(self,bg="black",highlightthickness=0)
        self._canvas.pack(fill="both",expand=True)
        self._lbl=tk.Label(self,text="",bg="black",fg="white",
                           font=("Segoe UI",14),anchor="s")
        self._lbl.place(relx=0.5,rely=0.95,anchor="center")
        self.bind("<space>",self._next_color)
        self.bind("<Escape>",lambda e:self.destroy())
        self.bind("<Button-1>",self._next_color)
        self._show()

    def _show(self):
        c=self._colors[self._idx%len(self._colors)]
        self.configure(bg=c); self._canvas.configure(bg=c)
        names=["Красный","Зелёный","Синий","Белый","Чёрный","Жёлтый","Пурпурный","Голубой","Серый"]
        txt=f"{names[self._idx%len(names)]}  —  {self._idx+1}/{len(self._colors)}  · Пробел/Клик = след.  · Esc = выход"
        fg="#000" if c in("#FFFFFF","#FFFF00","#00FFFF","#00FF00") else "#FFF"
        self._lbl.configure(text=txt,bg=c,fg=fg)
        # Сетка для поиска мёртвых пикселей
        if c=="#000000":
            self._canvas.delete("all")
            W,H=self.winfo_screenwidth(),self.winfo_screenheight()
            for x in range(0,W,50): self._canvas.create_line(x,0,x,H,fill="#111",width=1)
            for y in range(0,H,50): self._canvas.create_line(0,y,W,y,fill="#111",width=1)
            self._lbl.configure(text=txt+" · Ищите яркие пиксели на чёрном фоне")

    def _next_color(self,event=None):
        self._idx+=1; self._canvas.delete("all"); self._show()


class _MetaWindow(tk.Toplevel):
    """Окно просмотра метаданных."""
    def __init__(self,parent,path):
        super().__init__(parent)
        self.title(f"Метаданные — {os.path.basename(path)}")
        self.geometry("560x440"); self.configure(bg="#1E1E1E")
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text=f"  🏷 {os.path.basename(path)}",
                 bg="#264F78",fg="white",font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        self._tree=ttk.Treeview(self,columns=("val",),show="tree headings")
        self._tree.heading("#0",  text="Поле")
        self._tree.heading("val", text="Значение")
        self._tree.column("#0",width=180,minwidth=100)
        self._tree.column("val",width=340,minwidth=100)
        vsb=ttk.Scrollbar(self,command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); self._tree.pack(fill="both",expand=True,padx=4,pady=4)
        threading.Thread(target=self._load,args=(path,),daemon=True).start()

    def _load(self,path):
        meta=META.read(path)
        self.after(0,self._populate,meta)

    def _populate(self,meta):
        fmt=meta.pop("format","Метаданные")
        root=self._tree.insert("","end",text=fmt,open=True)
        if not meta or (len(meta)==1 and "error" in meta):
            self._tree.insert(root,"end",text="(нет метаданных)",values=(meta.get("error",""),))
            return
        for k,v in meta.items():
            self._tree.insert(root,"end",text=k,values=(str(v)[:200],))


class _StegoWindow(tk.Toplevel):
    """Окно LSB-анализа стеганографии."""
    def __init__(self,parent,path):
        super().__init__(parent)
        self.title(f"LSB-анализ — {os.path.basename(path)}")
        self.geometry("500x360"); self.configure(bg="#1E1E1E"); self.grab_set()
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔍 Анализ стеганографии (LSB)",
                 bg="#264F78",fg="white",font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        self._txt=tk.Text(self,font=("Consolas",9),bg="#0D0D0D",fg="#D4D4D4",
                          state="disabled",relief="flat",padx=8,pady=6)
        self._txt.pack(fill="both",expand=True,padx=6,pady=6)
        self._txt.tag_configure("ok",   foreground="#4EC94E",font=("Consolas",9,"bold"))
        self._txt.tag_configure("warn", foreground="#FFCC44",font=("Consolas",9,"bold"))
        self._txt.tag_configure("err",  foreground="#FF6666",font=("Consolas",9,"bold"))
        self._txt.tag_configure("key",  foreground="#569CD6",font=("Consolas",9,"bold"))
        self._txt.tag_configure("val",  foreground="#D4D4D4")
        tk.Label(self,text="Анализируется…",bg="#007ACC",fg="white",
                 font=("Segoe UI",8),anchor="w").pack(fill="x",side="bottom")
        threading.Thread(target=self._run,args=(path,),daemon=True).start()

    def _run(self,path):
        r=STEGO.analyze(path)
        self.after(0,self._show,r)

    def _show(self,r):
        t=self._txt; t.configure(state="normal"); t.delete("1.0","end")
        if "error" in r:
            t.insert("end",f"Ошибка: {r['error']}\n","err"); t.configure(state="disabled"); return
        def kv(k,v,tag="val"): t.insert("end",f"  {k:<22}","key"); t.insert("end",f"{v}\n",tag)
        kv("Размер:",        r.get("size","?"))
        kv("Пикселей:",      r.get("total_pixels","?"))
        t.insert("end","\n")
        t.insert("end","  LSB случайность каналов:\n","key")
        kv("  Red LSB:",   r.get("lsb_r","?"))
        kv("  Green LSB:", r.get("lsb_g","?"))
        kv("  Blue LSB:",  r.get("lsb_b","?"))
        kv("  Среднее:",   r.get("lsb_avg","?"))
        t.insert("end","\n")
        kv("Chi² (R-канал):",r.get("chi2_r","—"))
        kv("Chi² вердикт:",  r.get("chi2_verdict","—"))
        t.insert("end","\n")
        lvl=r.get("level","ok")
        tag={"ok":"ok","warn":"warn","info":"warn"}.get(lvl,"ok")
        t.insert("end",f"  ВЕРДИКТ: {r.get('verdict','?')}\n",(tag,"key"))
        score=r.get("suspicion_score",0)
        bar="█"*int(score*20)+"░"*(20-int(score*20))
        kv("Индекс подозр.:", f"{score:.2f}  [{bar}]")
        t.configure(state="disabled")


class _ProcessWindow(tk.Toplevel):
    """Процессы и автозагрузка."""
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Сканирование процессов и автозагрузки")
        self.geometry("820x560"); self.configure(bg="#1E1E1E")
        nb=ttk.Notebook(self); nb.pack(fill="both",expand=True,padx=4,pady=4)

        # Вкладка процессов
        f_proc=tk.Frame(nb,bg="#1E1E1E"); nb.add(f_proc,text="  Процессы  ")
        cols=("pid","name","cpu","mem","status","flag")
        self._ptree=ttk.Treeview(f_proc,columns=cols,show="headings")
        for c,w,t in (("pid",55,"PID"),("name",160,"Имя"),("cpu",60,"CPU%"),
                      ("mem",80,"Память"),("status",80,"Статус"),("flag",80,"")):
            self._ptree.heading(c,text=t); self._ptree.column(c,width=w,anchor="center" if c!="name" else "w")
        self._ptree.tag_configure("sus",foreground="#FF6666",font=("Consolas",8,"bold"))
        vsb=ttk.Scrollbar(f_proc,command=self._ptree.yview)
        self._ptree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); self._ptree.pack(fill="both",expand=True)

        # Вкладка автозагрузки
        f_auto=tk.Frame(nb,bg="#1E1E1E"); nb.add(f_auto,text="  Автозагрузка  ")
        cols2=("location","name","value","flag")
        self._atree=ttk.Treeview(f_auto,columns=cols2,show="headings")
        for c,w,t in (("location",180,"Расположение"),("name",120,"Имя"),
                      ("value",280,"Значение"),("flag",60,"")):
            self._atree.heading(c,text=t); self._atree.column(c,width=w)
        self._atree.tag_configure("sus",foreground="#FF6666",font=("Consolas",8,"bold"))
        vsb2=ttk.Scrollbar(f_auto,command=self._atree.yview)
        self._atree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right",fill="y"); self._atree.pack(fill="both",expand=True)

        sb=tk.Label(self,text="  Загружается…",bg="#007ACC",fg="white",font=("Segoe UI",8),anchor="w")
        sb.pack(fill="x",side="bottom"); self._sb=sb
        threading.Thread(target=self._load,daemon=True).start()

    def _load(self):
        procs=PROC_SCANNER.scan_processes()
        runs=PROC_SCANNER.scan_autorun()
        self.after(0,self._populate,procs,runs)

    def _populate(self,procs,runs):
        for p in procs:
            if "error" in p: continue
            flag="🚨 ПОДОЗР." if p.get("suspicious") else ""
            tag=("sus",) if p.get("suspicious") else ()
            self._ptree.insert("","end",
                values=(p["pid"],p["name"],p.get("cpu","?"),p["mem"],p["status"],flag),tags=tag)
        sus=sum(1 for p in procs if p.get("suspicious"))
        for a in runs:
            flag="🚨" if a.get("suspicious") else ""
            tag=("sus",) if a.get("suspicious") else ()
            self._atree.insert("","end",
                values=(a.get("location","?")[:40],a.get("name","?")[:30],
                        a.get("value","?")[:60],flag),tags=tag)
        self._sb.configure(text=f"  Процессов: {len(procs)}  Подозрительных: {sus}  Записей автозапуска: {len(runs)}")


class _NetworkWindow(tk.Toplevel):
    """Тест сети."""
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Тест сети — Wi-Fi / Ethernet")
        self.geometry("540x420"); self.configure(bg="#1E1E1E")
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  📡 Диагностика сети",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        self._prog=ttk.Progressbar(self,mode="indeterminate"); self._prog.pack(fill="x",padx=8,pady=4)
        self._txt=tk.Text(self,font=("Consolas",9),bg="#0D0D0D",fg="#D4D4D4",
                          state="disabled",relief="flat",padx=8,pady=4)
        self._txt.pack(fill="both",expand=True,padx=6,pady=4)
        self._txt.tag_configure("ok",   foreground="#4EC94E")
        self._txt.tag_configure("warn", foreground="#FFCC44")
        self._txt.tag_configure("key",  foreground="#569CD6",font=("Consolas",9,"bold"))
        btn=tk.Button(self,text="▶ Запустить тест",command=self._start,
                      bg="#264F78",fg="white",font=("Segoe UI",9),relief="flat",cursor="hand2")
        btn.pack(pady=6); self._btn=btn

    def _start(self):
        self._btn.configure(state="disabled"); self._prog.start(8)
        self._txt.configure(state="normal"); self._txt.delete("1.0","end"); self._txt.configure(state="disabled")
        threading.Thread(target=self._run,daemon=True).start()

    def _run(self):
        r=DEV.network_test(progress_cb=lambda m:self.after(0,self._log,m))
        self.after(0,self._done,r)

    def _log(self,msg):
        self._txt.configure(state="normal")
        self._txt.insert("end",f"  {msg}\n","ok")
        self._txt.see("end"); self._txt.configure(state="disabled")

    def _done(self,r):
        self._prog.stop(); self._btn.configure(state="normal")
        self._txt.configure(state="normal")
        self._txt.insert("end","\n  ─── Итог ───\n","key")
        kv=lambda k,v: (self._txt.insert("end",f"  {k:<22}","key"),self._txt.insert("end",f"{v}\n","ok"))
        kv("Ping:",    f"{r['ping_ms']} мс" if r['ping_ms'] else "нет ответа")
        kv("Скачивание:", f"{r['download_mbps']} Мбит/с" if r['download_mbps'] else "—")
        kv("Потери пакетов:", f"{r['packet_loss']}%" if r['packet_loss'] is not None else "—")
        self._txt.configure(state="disabled")


class _BatteryWindow(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Состояние аккумулятора")
        self.geometry("420x300"); self.configure(bg="#1E1E1E"); self.grab_set()
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔋 Аккумулятор",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        self._txt=tk.Text(self,font=("Consolas",9),bg="#0D0D0D",fg="#D4D4D4",
                          state="disabled",relief="flat",padx=8,pady=6)
        self._txt.pack(fill="both",expand=True,padx=6,pady=6)
        self._txt.tag_configure("key",foreground="#569CD6",font=("Consolas",9,"bold"))
        self._txt.tag_configure("val",foreground="#D4D4D4")
        self._txt.tag_configure("ok", foreground="#4EC94E")
        self._txt.tag_configure("warn",foreground="#FFCC44")
        threading.Thread(target=self._load,daemon=True).start()

    def _load(self):
        r=DEV.battery()
        self.after(0,self._show,r)

    def _show(self,r):
        t=self._txt; t.configure(state="normal"); t.delete("1.0","end")
        def kv(k,v,tag="val"): t.insert("end",f"  {k:<22}","key"); t.insert("end",f"{v}\n",tag)
        if not r.get("available"):
            t.insert("end","  Батарея не обнаружена или нет доступа\n","warn")
        else:
            pct=r.get("percent",0)
            tag="ok" if pct>50 else "warn" if pct>20 else "err"
            bar="█"*int(pct/5)+"░"*(20-int(pct/5))
            kv("Заряд:", f"{pct}%  [{bar}]",tag)
            kv("Питание:", "от сети" if r.get("plugged") else "от батареи")
            if r.get("time_left"): kv("Осталось:", r["time_left"])
            if r.get("cycles"):    kv("Циклов зарядки:", r["cycles"])
            if r.get("health"):    kv("Здоровье батареи:", f"{r['health']}%",
                                      "ok" if r["health"]>80 else "warn")
        t.configure(state="disabled")


class _BTWindow(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Bluetooth")
        self.geometry("480x360"); self.configure(bg="#1E1E1E")
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔵 Bluetooth",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        self._prog=ttk.Progressbar(self,mode="indeterminate"); self._prog.pack(fill="x",padx=8,pady=4)
        self._txt=tk.Text(self,font=("Consolas",9),bg="#0D0D0D",fg="#D4D4D4",
                          state="disabled",relief="flat",padx=8,pady=4)
        self._txt.pack(fill="both",expand=True,padx=6,pady=4)
        self._txt.tag_configure("ok",  foreground="#4EC94E")
        self._txt.tag_configure("info",foreground="#569CD6")
        btn=tk.Button(self,text="🔍 Сканировать",command=self._start,
                      bg="#264F78",fg="white",font=("Segoe UI",9),relief="flat",cursor="hand2")
        btn.pack(pady=6); self._btn=btn

    def _start(self):
        self._btn.configure(state="disabled"); self._prog.start(8)
        self._txt.configure(state="normal"); self._txt.delete("1.0","end"); self._txt.configure(state="disabled")
        threading.Thread(target=self._run,daemon=True).start()

    def _run(self):
        r=DEV.bluetooth_scan(progress_cb=lambda m:self.after(0,self._log,m,"info"))
        self.after(0,self._done,r)

    def _log(self,msg,tag="info"):
        self._txt.configure(state="normal")
        self._txt.insert("end",f"  {msg}\n",tag); self._txt.see("end"); self._txt.configure(state="disabled")

    def _done(self,r):
        self._prog.stop(); self._btn.configure(state="normal")
        self._log(f"Найдено устройств: {len(r['devices'])}","ok")
        for d in r["devices"]:
            self._log(f"  • {d.get('name','?')}  {d.get('mac','')}","ok")


class _USBWindow(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.title("USB-устройства")
        self.geometry("560x380"); self.configure(bg="#1E1E1E")
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔌 USB-порты и устройства",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)
        cols=("bus","dev","id","name")
        self._tree=ttk.Treeview(self,columns=cols,show="headings")
        for c,w,t in (("bus",40,"Bus"),("dev",40,"Dev"),("id",100,"ID"),("name",340,"Устройство")):
            self._tree.heading(c,text=t); self._tree.column(c,width=w)
        vsb=ttk.Scrollbar(self,command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); self._tree.pack(fill="both",expand=True)
        self._sb=tk.Label(self,text="  Загружается…",bg="#007ACC",fg="white",font=("Segoe UI",8),anchor="w")
        self._sb.pack(fill="x",side="bottom")
        threading.Thread(target=self._load,daemon=True).start()

    def _load(self):
        devs=DEV.usb_info()
        self.after(0,self._populate,devs)

    def _populate(self,devs):
        for d in devs:
            self._tree.insert("","end",
                values=(d.get("bus",""),d.get("dev",""),d.get("id",""),d.get("name","?")))
        self._sb.configure(text=f"  Устройств: {len(devs)}")


class _SpeakerWindow(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.title("Тест динамиков")
        self.geometry("420x300"); self.configure(bg="#1E1E1E"); self.grab_set()
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔊 Тест динамиков",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)

        body=tk.Frame(self,bg="#1E1E1E"); body.pack(fill="both",expand=True,padx=16,pady=8)
        tk.Label(body,text="Частота (Гц):",bg="#1E1E1E",fg="#D4D4D4",
                 font=("Segoe UI",9)).grid(row=0,column=0,sticky="w",pady=4)
        self._freq=tk.Scale(body,from_=100,to=8000,orient="horizontal",length=280,
                            bg="#1E1E1E",fg="#D4D4D4",troughcolor="#264F78",highlightthickness=0)
        self._freq.set(1000); self._freq.grid(row=0,column=1,pady=4)

        tk.Label(body,text="Длительность (сек):",bg="#1E1E1E",fg="#D4D4D4",
                 font=("Segoe UI",9)).grid(row=1,column=0,sticky="w",pady=4)
        self._dur=tk.Scale(body,from_=0.5,to=5.0,resolution=0.5,orient="horizontal",length=280,
                           bg="#1E1E1E",fg="#D4D4D4",troughcolor="#264F78",highlightthickness=0)
        self._dur.set(1.0); self._dur.grid(row=1,column=1,pady=4)

        freqs=[(100,"Суббас"),(300,"Бас"),(1000,"Средние"),(3000,"Выс. средние"),(8000,"Высокие")]
        pf=tk.Frame(body,bg="#1E1E1E"); pf.grid(row=2,column=0,columnspan=2,pady=8)
        for hz,lbl in freqs:
            tk.Button(pf,text=f"{lbl}\n{hz} Гц",
                      command=lambda h=hz:self._play(h,1.0),
                      bg="#264F78",fg="white",font=("Segoe UI",8),relief="flat",
                      cursor="hand2",width=9).pack(side="left",padx=3)

        self._status=tk.Label(self,text="  Готов",bg="#007ACC",fg="white",
                              font=("Segoe UI",8),anchor="w")
        self._status.pack(fill="x",side="bottom")

        tk.Button(self,text="▶ Воспроизвести",command=lambda:self._play(int(self._freq.get()),self._dur.get()),
                  bg="#264F78",fg="white",font=("Segoe UI",10),relief="flat",cursor="hand2"
                  ).pack(pady=6)

    def _play(self,freq,dur):
        self._status.configure(text=f"  Воспроизведение {freq} Гц…")
        threading.Thread(target=self._do_play,args=(freq,dur),daemon=True).start()

    def _do_play(self,freq,dur):
        r=DEV.speaker_test(freq,dur)
        self.after(0,lambda:self._status.configure(
            text=f"  {freq} Гц — {'OK' if r['status']=='ok' else r['status']}"))


class _SchedulerWindow(tk.Toplevel):
    """Планировщик сканирования."""
    def __init__(self,parent,scheduler,file_paths):
        super().__init__(parent)
        self.title("Планировщик сканирования")
        self.geometry("520x340"); self.configure(bg="#1E1E1E")
        self._sched=scheduler; self._paths=file_paths
        hdr=tk.Frame(self,bg="#264F78",height=32); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  ⏰ Планировщик",bg="#264F78",fg="white",
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=8,pady=4)

        body=tk.Frame(self,bg="#1E1E1E"); body.pack(fill="both",expand=True,padx=16,pady=8)

        tk.Label(body,text="Название задачи:",bg="#1E1E1E",fg="#D4D4D4",
                 font=("Segoe UI",9)).grid(row=0,column=0,sticky="w",pady=4)
        self._name=tk.Entry(body,font=("Segoe UI",9),bg="#252526",fg="white",width=24)
        self._name.insert(0,"Авто-сканирование"); self._name.grid(row=0,column=1,pady=4,padx=8)

        tk.Label(body,text="Интервал (минут):",bg="#1E1E1E",fg="#D4D4D4",
                 font=("Segoe UI",9)).grid(row=1,column=0,sticky="w",pady=4)
        self._interval=tk.Scale(body,from_=5,to=1440,resolution=5,orient="horizontal",
                                 length=200,bg="#1E1E1E",fg="#D4D4D4",troughcolor="#264F78",
                                 highlightthickness=0)
        self._interval.set(60); self._interval.grid(row=1,column=1,pady=4,padx=8)

        tk.Label(body,text=f"Файлов в очереди: {len(file_paths)}",
                 bg="#1E1E1E",fg="#888",font=("Segoe UI",8)).grid(row=2,column=0,columnspan=2,pady=4)

        btn_frame=tk.Frame(body,bg="#1E1E1E"); btn_frame.grid(row=3,column=0,columnspan=2,pady=12)
        tk.Button(btn_frame,text="➕ Добавить задачу",command=self._add,
                  bg="#264F78",fg="white",font=("Segoe UI",9),relief="flat",cursor="hand2"
                  ).pack(side="left",padx=4)
        tk.Button(btn_frame,text="🗑 Удалить выбранную",command=self._remove,
                  bg="#4B1113",fg="white",font=("Segoe UI",9),relief="flat",cursor="hand2"
                  ).pack(side="left",padx=4)

        self._listbox=tk.Listbox(body,bg="#252526",fg="#D4D4D4",font=("Consolas",8),height=5)
        self._listbox.grid(row=4,column=0,columnspan=2,sticky="ew",pady=4)
        self._refresh()

        self._sb=tk.Label(self,text="  Планировщик активен" if scheduler._active else "  Планировщик остановлен",
                          bg="#007ACC",fg="white",font=("Segoe UI",8),anchor="w")
        self._sb.pack(fill="x",side="bottom")

    def _add(self):
        name=self._name.get().strip()
        if not name: return
        interval=int(self._interval.get())
        self._sched.add_job(name,interval,list(self._paths))
        if not self._sched._active: self._sched.start()
        self._refresh()
        self._sb.configure(text=f"  Задача «{name}» добавлена (каждые {interval} мин)")

    def _remove(self):
        sel=self._listbox.curselection()
        if not sel: return
        item=self._listbox.get(sel[0])
        label=item.split("]")[0].strip("[ ")
        self._sched.remove_job(label)
        self._refresh()

    def _refresh(self):
        self._listbox.delete(0,"end")
        for job in self._sched._jobs:
            nxt=job["next"].strftime("%H:%M")
            self._listbox.insert("end",f"[ {job['label']} ]  каждые {job['interval_min']}мин  следующий: {nxt}")

# ══════════════════════════════════════════════════════════════════════════════
#  ТЕМЫ
# ══════════════════════════════════════════════════════════════════════════════
THEMES={
"light":{"bg":"#F0F0F0","bg2":"#FAFAFA","fg":"#000000","fg2":"#333333",
         "accent":"#003399","accent_fg":"#FFFFFF","toolbar":"#F0F0F0","statusbar":"#D4D0C8",
         "sep":"#A0A0A0","tree_ok":"#005A00","tree_warn":"#7A5500","tree_err":"#8B0000",
         "tree_pend":"#606060","log_ok":"#005A00","log_warn":"#7A5500","log_err":"#8B0000",
         "log_info":"#00008B","log_threat":"#CC0000","detail_bg":"#FAFAFA","btn_hover":"#C8D8E8","pane_sash":"#C0C0C0"},
"dark": {"bg":"#1E1E1E","bg2":"#252526","fg":"#D4D4D4","fg2":"#AAAAAA",
         "accent":"#264F78","accent_fg":"#FFFFFF","toolbar":"#2D2D2D","statusbar":"#007ACC",
         "sep":"#555555","tree_ok":"#4EC94E","tree_warn":"#FFCC44","tree_err":"#FF6666",
         "tree_pend":"#888888","log_ok":"#4EC94E","log_warn":"#FFCC44","log_err":"#FF6666",
         "log_info":"#569CD6","log_threat":"#FF4444","detail_bg":"#252526","btn_hover":"#37373D","pane_sash":"#3C3C3C"},
}

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ ПРИЛОЖЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
class SonarApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self._lang  = "RU"
        self._theme = "dark"
        self.geometry("1100x700"); self.minsize(800,520)

        self._q            = queue.Queue()
        self._checker_inst = None   # FileChecker — создаётся в _build_ui
        self._running      = False
        self._results      = []
        self._file_paths   = []
        self._kbd_active   = False
        self._mouse_active = False
        self._log_entries  = []
        self._monitor      = FileMonitor(self._on_file_changed)
        self._scheduler    = Scheduler(self._scheduled_scan)

        self._build_ui()
        self._poll_queue()
        self._log("Sonar v3.0 запущен","info")
        c_st="активно" if CORE.available else "Python fallback"
        self._log(f"C-ядро: {c_st}","ok" if CORE.available else "warn")
        self._log(f"Вирусная БД: {len(VDB.signatures)} сигнатур","info")
        self._log(f"Pillow: {'есть' if HAS_PIL else 'нет (pip install Pillow)'}","info")
        self._log(f"Mutagen: {'есть' if HAS_MUTAGEN else 'нет (pip install mutagen)'}","info")
        self._log(f"psutil: {'есть' if HAS_PSUTIL else 'нет (pip install psutil)'}","info")

    @property
    def T(self): return THEMES[self._theme]

    def _build_ui(self):
        T=self.T
        self.title("Sonar v3.0 — Диагностика файлов и устройств")
        self.configure(bg=T["bg"])

        style=ttk.Style(self)
        for th in ("vista","winnative","clam","default"):
            try: style.theme_use(th); break
            except: pass

        # ── Меню ──────────────────────────────────────────────────────────
        mb=tk.Menu(self,tearoff=0,bg=T["toolbar"],fg=T["fg"])

        mf=tk.Menu(mb,tearoff=0,bg=T["toolbar"],fg=T["fg"])
        mf.add_command(label="Добавить файлы…",  accelerator="Ctrl+O",command=self._add_files)
        mf.add_command(label="Добавить папку…",  accelerator="Ctrl+D",command=self._add_folder)
        mf.add_separator()
        mf.add_command(label="Сохранить отчёт…", accelerator="Ctrl+S",command=self._export_report)
        mf.add_separator()
        mf.add_command(label="Выход",command=self.quit)
        mb.add_cascade(label="Файл",menu=mf)

        ms=tk.Menu(mb,tearoff=0,bg=T["toolbar"],fg=T["fg"])
        ms.add_command(label="Сканировать",       accelerator="F5",command=self._start_scan)
        ms.add_command(label="Детальный разбор",  accelerator="F6",command=self._start_deep)
        ms.add_separator()
        ms.add_command(label="Очистить список",command=self._clear)
        ms.add_command(label="Планировщик…",command=lambda:_SchedulerWindow(self,self._scheduler,self._file_paths))
        mb.add_cascade(label="Сканирование",menu=ms)

        mv=tk.Menu(mb,tearoff=0,bg=T["toolbar"],fg=T["fg"])
        mv.add_command(label="Детали выбранного",accelerator="Enter",command=self._show_details)
        mv.add_separator()
        mv.add_command(label="☀ Светлая тема", command=lambda:self._switch_theme("light"))
        mv.add_command(label="🌙 Тёмная тема",  command=lambda:self._switch_theme("dark"))
        mb.add_cascade(label="Вид",menu=mv)

        mt=tk.Menu(mb,tearoff=0,bg=T["toolbar"],fg=T["fg"])
        mt.add_command(label="🔎 Процессы и автозагрузка",command=lambda:_ProcessWindow(self))
        mt.add_command(label="⏰ Планировщик",command=lambda:_SchedulerWindow(self,self._scheduler,self._file_paths))
        mb.add_cascade(label="Инструменты",menu=mt)

        mh=tk.Menu(mb,tearoff=0,bg=T["toolbar"],fg=T["fg"])
        mh.add_command(label="О программе",command=self._about)
        mb.add_cascade(label="Справка",menu=mh)
        self.config(menu=mb)

        self.bind("<Control-o>",lambda e:self._add_files())
        self.bind("<Control-d>",lambda e:self._add_folder())
        self.bind("<Control-s>",lambda e:self._export_report())
        self.bind("<F5>",lambda e:self._start_scan())
        self.bind("<F6>",lambda e:self._start_deep())
        self.bind("<Return>",lambda e:self._show_details())

        # ── Тулбар ────────────────────────────────────────────────────────
        tb=tk.Frame(self,bg=T["toolbar"],relief="raised",bd=1,height=32)
        tb.pack(fill="x"); tb.pack_propagate(False)
        for txt,cmd in [("📄 Файлы",self._add_files),("📁 Папка",self._add_folder),
                        ("▶ Скан [F5]",self._start_scan),("🔬 Детальный [F6]",self._start_deep),
                        ("✕ Очистить",self._clear),("💾 Отчёт",self._export_report),
                        ("🔎 Процессы",lambda:_ProcessWindow(self)),
                        ("⏰ Планировщик",lambda:_SchedulerWindow(self,self._scheduler,self._file_paths))]:
            self._mk_tb_btn(txt,cmd,tb)
            if txt in("📁 Папка","🔬 Детальный [F6]","💾 Отчёт"):
                tk.Frame(tb,bg=T["sep"],width=1).pack(side="left",fill="y",padx=3,pady=3)

        # C-ядро бейдж
        c_txt="✓ C-ядро" if CORE.available else "✗ C-ядро"
        c_col=T["log_ok"] if CORE.available else T["log_err"]
        tk.Label(tb,text=f"  {c_txt}  |  БД: {len(VDB.signatures)} сигн.  ",
                 bg=T["toolbar"],fg=c_col,font=("Consolas",8)).pack(side="right",padx=4)
        th_lbl="☀" if self._theme=="light" else "🌙"
        tk.Label(tb,text=f"  {th_lbl}  ",bg=T["toolbar"],fg=T["fg"],
                 font=("Segoe UI",9)).pack(side="right")

        # ── Notebook ──────────────────────────────────────────────────────
        nb=ttk.Notebook(self); nb.pack(fill="both",expand=True)
        f_files=tk.Frame(nb,bg=T["bg"])
        f_dev  =tk.Frame(nb,bg=T["bg"])
        f_logs =tk.Frame(nb,bg=T["bg"])
        nb.add(f_files,text="   Файлы   ")
        nb.add(f_dev,  text="   Устройства   ")
        nb.add(f_logs, text="   Журнал   ")

        self._build_files_tab(f_files)
        self._build_devices_tab(f_dev)
        self._build_logs_tab(f_logs)

        # ── Статусбар ─────────────────────────────────────────────────────
        sbar=tk.Frame(self,bg=T["statusbar"],relief="sunken",bd=1,height=20)
        sbar.pack(fill="x",side="bottom"); sbar.pack_propagate(False)
        fg_s=T["accent_fg"] if self._theme=="dark" else T["fg"]
        self._status_left =tk.Label(sbar,text="  Готов",bg=T["statusbar"],fg=fg_s,font=("Segoe UI",8),anchor="w")
        self._status_left.pack(side="left",fill="x",expand=True,padx=4)
        self._status_right=tk.Label(sbar,text="",bg=T["statusbar"],fg=fg_s,font=("Segoe UI",8),anchor="e")
        self._status_right.pack(side="right",padx=4)

    def _mk_tb_btn(self,text,cmd,parent):
        T=self.T
        btn=tk.Button(parent,text=f" {text} ",command=cmd,
                      relief="flat",bg=T["toolbar"],fg=T["fg"],
                      activebackground=T["btn_hover"],activeforeground=T["fg"],
                      font=("Segoe UI",8),cursor="hand2",bd=0,highlightthickness=0)
        btn.pack(side="left",padx=1,pady=4)
        btn.bind("<Enter>",lambda e,b=btn:b.config(relief="raised",bg=T["btn_hover"]))
        btn.bind("<Leave>",lambda e,b=btn:b.config(relief="flat",bg=T["toolbar"]))

    def _switch_theme(self,theme):
        self._theme=theme
        self._log(f"Тема: {theme}","info")
        self._full_rebuild()

    def _full_rebuild(self):
        data={"paths":list(self._file_paths),"results":list(self._results),"logs":list(self._log_entries)}
        for w in self.winfo_children(): w.destroy()
        self.config(menu=tk.Menu(self))
        self._build_ui()
        self._file_paths=data["paths"]; self._results=data["results"]; self._log_entries=data["logs"]
        for path in data["paths"]:
            r=next((x for x in data["results"] if x["path"]==path),None)
            if r: self._update_row(r)
            else: self._insert_pending(path)
        for ts,lvl,msg in data["logs"]:
            self._log_text.configure(state="normal")
            self._log_text.insert("end",f"[{ts}] {msg}\n",lvl)
            self._log_text.see("end"); self._log_text.configure(state="disabled")
        self._poll_queue()

    # ─── Вкладка: Файлы ───────────────────────────────────────────────────
    def _build_files_tab(self,parent):
        T=self.T
        pane=tk.PanedWindow(parent,orient="horizontal",sashwidth=5,bg=T["pane_sash"],handlesize=0)
        pane.pack(fill="both",expand=True)

        left=tk.Frame(pane,bg=T["bg"]); pane.add(left,width=720)
        cols=("st","name","type","size","detail")
        self._tree=ttk.Treeview(left,columns=cols,show="headings",selectmode="browse")
        for c,w,t,a in (("st",26,"","center"),("name",220,"Файл","w"),("type",90,"Тип","center"),
                        ("size",80,"Размер","e"),("detail",380,"Результат","w")):
            self._tree.heading(c,text=t,anchor=a); self._tree.column(c,width=w,anchor=a)
        self._tree.tag_configure("ok",   foreground=T["tree_ok"])
        self._tree.tag_configure("warn", foreground=T["tree_warn"])
        self._tree.tag_configure("err",  foreground=T["tree_err"])
        self._tree.tag_configure("pending",foreground=T["tree_pend"])
        vsb=ttk.Scrollbar(left,orient="vertical",  command=self._tree.yview)
        hsb=ttk.Scrollbar(left,orient="horizontal",command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set,xscrollcommand=hsb.set)
        vsb.pack(side="right",fill="y"); hsb.pack(side="bottom",fill="x")
        self._tree.pack(fill="both",expand=True)
        self._tree.bind("<Double-1>",    lambda e:self._show_details())
        self._tree.bind("<<TreeviewSelect>>",self._on_sel)
        self._tree.bind("<Button-3>",    self._context_menu)

        # Drag & Drop (TkDND если есть, иначе заглушка)
        try:
            self._tree.drop_target_register("DND_Files")
            self._tree.dnd_bind("<<Drop>>", self._on_drop)
        except: pass

        right=tk.Frame(pane,bg=T["bg"]); pane.add(right,width=360)
        tk.Label(right,text="Сведения о файле",bg=T["bg"],fg=T["fg"],
                 font=("Segoe UI",9,"bold")).pack(anchor="w",padx=8,pady=(6,2))
        ttk.Separator(right,orient="horizontal").pack(fill="x",padx=4)
        self._detail_text=tk.Text(right,font=("Consolas",8),state="disabled",relief="flat",
                                   bg=T["detail_bg"],fg=T["fg"],wrap="word",cursor="arrow",padx=6,pady=4)
        self._detail_text.pack(fill="both",expand=True,padx=2,pady=2)

        prog=tk.Frame(parent,bg=T["bg"]); prog.pack(fill="x",padx=4,pady=(2,4))
        self._prog=ttk.Progressbar(prog,mode="determinate",length=260)
        self._prog.pack(side="left",padx=(0,6))
        self._prog_lbl=tk.Label(prog,text="Готов",bg=T["bg"],fg=T["fg"],font=("Segoe UI",8))
        self._prog_lbl.pack(side="left")
        self._prog_cnt=tk.Label(prog,text="",bg=T["bg"],fg=T["fg"],font=("Segoe UI",8))
        self._prog_cnt.pack(side="right")

    def _context_menu(self,event):
        sel=self._tree.identify_row(event.y)
        if not sel: return
        self._tree.selection_set(sel)
        path=sel
        ext=Path(path).suffix.lower()
        is_img=ext in('.png','.jpg','.jpeg','.gif','.bmp','.webp')
        is_txt=ext in('.txt','.log','.py','.js','.json','.xml','.csv','.ini','.cfg','.md','.html','.c','.h','.cpp')
        is_arch=ext in('.zip','.docx','.xlsx','.pptx','.jar','.apk','.gz','.bz2','.tar','.7z','.rar')

        menu=tk.Menu(self,tearoff=0,bg=self.T["toolbar"],fg=self.T["fg"])
        menu.add_command(label="🔬 Детальный разбор",command=lambda:self._start_deep_single(path))
        menu.add_command(label="🏷 Метаданные",command=lambda:_MetaWindow(self,path))
        if is_arch:
            menu.add_command(label="📦 Структура архива",command=lambda:_ArchiveViewWindow(self,path))
        if is_img:
            menu.add_command(label="🔍 LSB-стеганография",command=lambda:_StegoWindow(self,path))
        if is_txt:
            menu.add_command(label="📊 Сравнить построчно…",command=lambda:_DiffWindow(self,path))
        menu.add_separator()
        menu.add_command(label="🔧 Попытка восстановления",command=lambda:_RepairWindow(self,path))
        menu.add_separator()
        monitor_lbl="🔴 Снять с мониторинга" if path in self._monitor._watching else "👁 Мониторить файл"
        def toggle_mon():
            if path in self._monitor._watching:
                self._monitor.remove(path); self._log(f"Мониторинг остановлен: {os.path.basename(path)}","info")
            else:
                self._monitor.add(path); self._monitor.start(); self._log(f"Мониторинг: {os.path.basename(path)}","info")
        menu.add_command(label=monitor_lbl,command=toggle_mon)
        menu.add_separator()
        menu.add_command(label="📋 Копировать путь",command=lambda:(self.clipboard_clear(),self.clipboard_append(path)))
        menu.post(event.x_root,event.y_root)

    def _on_drop(self,event):
        files=self.tk.splitlist(event.data)
        for f in files:
            if os.path.exists(f) and f not in self._file_paths:
                self._file_paths.append(f); self._insert_pending(f)

    def _on_sel(self,event):
        sel=self._tree.selection()
        if not sel: return
        res=next((r for r in self._results if r["path"]==sel[0]),None)
        if res: self._render_details(res)

    def _render_details(self,res):
        T=self.T; t=self._detail_text
        t.configure(state="normal"); t.delete("1.0","end")
        t.configure(bg=T["detail_bg"],fg=T["fg"])
        t.tag_configure("head",font=("Segoe UI",8,"bold"),foreground=T["fg"])
        t.tag_configure("ok",  foreground=T["tree_ok"])
        t.tag_configure("warn",foreground=T["tree_warn"])
        t.tag_configure("err", foreground=T["tree_err"])
        t.tag_configure("key", font=("Consolas",7,"bold"),foreground=T["fg2"])
        t.tag_configure("val", font=("Consolas",7),foreground=T["fg"])
        t.tag_configure("thr_d",foreground=T["log_threat"],font=("Segoe UI",8,"bold"))
        t.tag_configure("thr_w",foreground=T["log_warn"])
        t.tag_configure("thr_c",foreground=T["log_ok"])

        sm={"ok":("✓ ИСПРАВЕН","ok"),"warn":("⚠ ВНИМАНИЕ","warn"),"error":("✗ ПОВРЕЖДЁН","err")}
        st,sg=sm.get(res["status"],("?",""))
        t.insert("end",f"{st}\n",(sg,"head"))
        t.insert("end","─"*30+"\n","key")
        for k,v in (("Имя",res["name"]),("Тип",res["type"]),("Размер",_fmt(res["size"]))):
            t.insert("end",f"{k:<9}","key"); t.insert("end",f"{v}\n","val")

        if res.get("details"):
            t.insert("end","\nДетали:\n","head")
            for d in res["details"]: t.insert("end",f"  {d}\n","val")
        if res.get("issues"):
            t.insert("end","\nПроблемы:\n","head")
            for i in res["issues"]: t.insert("end",f"  ⚠ {i}\n",("warn","val"))

        deep=res.get("deep")
        if deep:
            t.insert("end","\n🔬 Глубокий анализ:\n","head")
            for k,v in (("CRC-32",deep.get("crc32","—")),
                        ("Энтропия",f"{deep.get('entropy','—')} бит/байт"),
                        ("",deep.get("entropy_hint","")),
                        ("Нули",f"{deep.get('null_ratio','—')}%  {deep.get('null_hint','')}"),
                        ("ASCII",f"{deep.get('ascii_ratio','—')}% ({deep.get('content_class','—')})"),
                        ("C-ядро","✓ да" if deep.get("c_backend") else "✗ Python fallback")):
                t.insert("end",f"  {k:<10}","key"); t.insert("end",f"{v}\n","val")

            if deep.get("top_bytes"):
                t.insert("end","\n  Топ-5 байт:\n","head")
                for b in deep["top_bytes"]:
                    t.insert("end",f"    {b['byte']} '{b['char']}' → {b['count']} ({b['pct']}%)\n","val")

            if deep.get("extra"):
                t.insert("end","\n  Структура:\n","head")
                for line in deep["extra"]: t.insert("end",f"  {line}\n","val")

            # Метаданные
            meta=deep.get("meta")
            if meta and len(meta)>1:
                t.insert("end","\n🏷 Метаданные:\n","head")
                for k,v in list(meta.items())[:12]:
                    if k!="format": t.insert("end",f"  {k[:18]:<18}","key"); t.insert("end",f"{str(v)[:60]}\n","val")

            # Стеганография
            stego=deep.get("stego")
            if stego and not stego.get("error"):
                t.insert("end","\n🔍 LSB-анализ:\n","head")
                t.insert("end",f"  {stego.get('verdict','?')}\n",
                         {"ok":"thr_c","warn":"thr_w"}.get(stego.get("level","ok"),"val"))
                t.insert("end",f"  LSB avg: {stego.get('lsb_avg','?')}  χ²: {stego.get('chi2_r','?')}\n","val")

            # Архив
            arch=deep.get("archive")
            if arch and "stats" in arch:
                s=arch["stats"]
                t.insert("end","\n📦 Архив:\n","head")
                t.insert("end",f"  Файлов: {s.get('total_files','?')}  {s.get('compressed','?')}→{s.get('uncompressed','?')}\n","val")
                if s.get("zip_bomb_risk"):
                    t.insert("end","  🚨 ZIP-БОМБА!\n","thr_d")

            # Угрозы
            threat=deep.get("threat")
            if threat:
                t.insert("end","\n🛡 Анализ угроз:\n","head")
                lvl=threat.get("level","clean")
                lbl={"clean":"✓ Угроз не обнаружено","suspicious":"⚠ Подозрительный","danger":"🚨 ВЕРОЯТНО ВРЕДОНОСНЫЙ"}[lvl]
                tag={"clean":"thr_c","suspicious":"thr_w","danger":"thr_d"}[lvl]
                t.insert("end",f"  {lbl}\n",(tag,"head"))
                for r2 in threat.get("reasons",[]):
                    tg="thr_d" if "🚨" in r2 else "thr_w"
                    t.insert("end",f"  {r2}\n",tg)

            probs=deep.get("verdict_problems",[])
            if probs:
                t.insert("end","\n  ⚠ Итог:\n",("warn","head"))
                for p in probs: t.insert("end",f"    • {p}\n",("warn","val"))
            else:
                t.insert("end","\n  ✓ Проблем не обнаружено\n",("ok","val"))

        t.configure(state="disabled")

    # ─── Вкладка: Устройства ──────────────────────────────────────────────
    def _build_devices_tab(self,parent):
        T=self.T
        pane=tk.PanedWindow(parent,orient="horizontal",sashwidth=5,bg=T["pane_sash"],handlesize=0)
        pane.pack(fill="both",expand=True)

        # Дерево устройств (слева)
        left=tk.Frame(pane,bg=T["bg"]); pane.add(left,width=280)

        hdr2=tk.Frame(left,bg=T["accent"],height=28); hdr2.pack(fill="x"); hdr2.pack_propagate(False)
        tk.Label(hdr2,text="  Диспетчер устройств",bg=T["accent"],fg=T["accent_fg"],
                 font=("Segoe UI",8,"bold")).pack(side="left",padx=6,pady=4)

        self._dev_tree=ttk.Treeview(left,show="tree",selectmode="browse")
        dev_vsb=ttk.Scrollbar(left,command=self._dev_tree.yview)
        self._dev_tree.configure(yscrollcommand=dev_vsb.set)
        dev_vsb.pack(side="right",fill="y"); self._dev_tree.pack(fill="both",expand=True)

        # Заполняем дерево — структура как в Диспетчере устройств
        root_id=self._dev_tree.insert("","end",text="💻 Этот компьютер",open=True)

        inp_id=self._dev_tree.insert(root_id,"end",text="🖱 Устройства ввода",open=True)
        self._kbd_node  =self._dev_tree.insert(inp_id,"end",text="⌨  Клавиатура  [не проверено]")
        self._mouse_node=self._dev_tree.insert(inp_id,"end",text="🖱  Мышь  [не проверено]")

        aud_id=self._dev_tree.insert(root_id,"end",text="🔊 Звук",open=True)
        self._mic_node  =self._dev_tree.insert(aud_id,"end",text="🎤  Микрофон  [не проверено]")
        self._spk_node  =self._dev_tree.insert(aud_id,"end",text="🔊  Динамики  [не проверено]")

        disp_id=self._dev_tree.insert(root_id,"end",text="🖥 Дисплей",open=True)
        self._disp_node =self._dev_tree.insert(disp_id,"end",text="🖥  Тест дисплея  [не проверено]")

        pc_id=self._dev_tree.insert(root_id,"end",text="🖥 ПК / Система",open=True)
        self._bat_node  =self._dev_tree.insert(pc_id,"end",text="🔋  Аккумулятор  [не проверено]")
        self._net_node  =self._dev_tree.insert(pc_id,"end",text="📡  Wi-Fi / Сеть  [не проверено]")
        self._bt_node   =self._dev_tree.insert(pc_id,"end",text="🔵  Bluetooth  [не проверено]")

        usb_id=self._dev_tree.insert(root_id,"end",text="🔌 USB",open=True)
        self._usb_node  =self._dev_tree.insert(usb_id,"end",text="🔌  USB-порты  [не проверено]")

        self._dev_tree.bind("<Double-1>",self._dev_tree_action)

        # Правая часть — свойства
        right=tk.Frame(pane,bg=T["bg"]); pane.add(right)

        phdr=tk.Frame(right,bg=T["bg2"],relief="groove",bd=1,height=28)
        phdr.pack(fill="x"); phdr.pack_propagate(False)
        tk.Label(phdr,text=" Свойства устройства",bg=T["bg2"],fg=T["fg"],
                 font=("Segoe UI",8,"bold")).pack(side="left",padx=6,pady=4)

        cards=tk.Frame(right,bg=T["bg"]); cards.pack(fill="x",padx=8,pady=8)
        self._kbd_card  =self._dev_card(cards,"⌨ Клавиатура",   0,self._test_keyboard)
        self._mouse_card=self._dev_card(cards,"🖱 Мышь",         1,self._test_mouse)
        self._mic_card  =self._dev_card(cards,"🎤 Микрофон",     2,self._test_mic)

        cards2=tk.Frame(right,bg=T["bg"]); cards2.pack(fill="x",padx=8,pady=4)
        self._dev_card(cards2,"🔊 Динамики",    0,self._test_speakers)
        self._dev_card(cards2,"🖥 Дисплей",     1,lambda:DEV.display_test(self))
        self._dev_card(cards2,"🔋 Батарея",     2,lambda:_BatteryWindow(self))

        cards3=tk.Frame(right,bg=T["bg"]); cards3.pack(fill="x",padx=8,pady=4)
        self._dev_card(cards3,"📡 Сеть",        0,lambda:_NetworkWindow(self))
        self._dev_card(cards3,"🔵 Bluetooth",   1,lambda:_BTWindow(self))
        self._dev_card(cards3,"🔌 USB",         2,lambda:_USBWindow(self))

        ehdr=tk.Frame(right,bg=T["bg2"],relief="groove",bd=1,height=22)
        ehdr.pack(fill="x",padx=8,pady=(8,0)); ehdr.pack_propagate(False)
        tk.Label(ehdr,text=" Журнал событий",bg=T["bg2"],fg=T["fg"],
                 font=("Segoe UI",8,"bold")).pack(side="left",padx=6)

        lf=tk.Frame(right,bg=T["bg"]); lf.pack(fill="both",expand=True,padx=8,pady=(0,8))
        self._dev_log=tk.Text(lf,height=6,state="disabled",font=("Consolas",8),
                               relief="sunken",bd=1,wrap="word",cursor="arrow",
                               bg=T["detail_bg"],fg=T["fg"])
        lsb=ttk.Scrollbar(lf,command=self._dev_log.yview)
        self._dev_log.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right",fill="y"); self._dev_log.pack(fill="both",expand=True)
        for tag,col in (("ok",T["log_ok"]),("warn",T["log_warn"]),("err",T["log_err"]),("info",T["log_info"])):
            self._dev_log.tag_config(tag,foreground=col)

        self.bind("<KeyPress>",    self._on_key)
        self.bind("<ButtonPress>", self._on_click)
        self.bind("<MouseWheel>",  self._on_scroll)
        self.bind("<Button-4>",    self._on_scroll)
        self.bind("<Button-5>",    self._on_scroll)

    def _dev_card(self,parent,title,col,cmd):
        T=self.T
        lf=ttk.LabelFrame(parent,text=title,padding=4)
        lf.grid(row=0,column=col,padx=3,pady=2,sticky="nsew")
        parent.columnconfigure(col,weight=1)
        sv=tk.StringVar(value="— не проверено —")
        ttk.Label(lf,textvariable=sv,wraplength=110,justify="center",
                  font=("Segoe UI",7)).pack(pady=(2,4),fill="x")
        ttk.Button(lf,text="Проверить",width=12,command=cmd).pack()
        return {"sv":sv}

    def _dev_tree_action(self,event):
        sel=self._dev_tree.selection()
        if not sel: return
        node=sel[0]
        if node==self._bat_node:   _BatteryWindow(self)
        elif node==self._net_node: _NetworkWindow(self)
        elif node==self._bt_node:  _BTWindow(self)
        elif node==self._usb_node: _USBWindow(self)
        elif node==self._spk_node: self._test_speakers()
        elif node==self._disp_node:DEV.display_test(self)
        elif node==self._kbd_node: self._test_keyboard()
        elif node==self._mouse_node:self._test_mouse()
        elif node==self._mic_node: self._test_mic()

    # ─── Вкладка: Логи ────────────────────────────────────────────────────
    def _build_logs_tab(self,parent):
        T=self.T
        hdr=tk.Frame(parent,bg=T["accent"],height=28); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  📋 Системный журнал Sonar",bg=T["accent"],fg=T["accent_fg"],
                 font=("Segoe UI",9,"bold")).pack(side="left",padx=6,pady=4)
        tb2=tk.Frame(parent,bg=T["toolbar"],relief="raised",bd=1,height=26)
        tb2.pack(fill="x"); tb2.pack_propagate(False)
        for txt,cmd in [("🗑 Очистить",self._clear_logs),("💾 Экспорт…",self._export_logs)]:
            tk.Button(tb2,text=txt,command=cmd,relief="flat",bg=T["toolbar"],fg=T["fg"],
                      font=("Segoe UI",8),cursor="hand2").pack(side="left",padx=4,pady=2)
        frame=tk.Frame(parent,bg=T["bg"]); frame.pack(fill="both",expand=True,padx=6,pady=6)
        self._log_text=tk.Text(frame,font=("Consolas",8),state="disabled",relief="sunken",bd=1,
                                wrap="word",cursor="arrow",bg=T["detail_bg"],fg=T["fg"])
        lsb=ttk.Scrollbar(frame,command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right",fill="y"); self._log_text.pack(fill="both",expand=True)
        for tag,col in (("ok",T["log_ok"]),("warn",T["log_warn"]),("err",T["log_err"]),
                        ("info",T["log_info"]),("threat",T["log_threat"])):
            self._log_text.tag_config(tag,foreground=col)

    def _log(self,text,level="info"):
        ts=_ts()
        self._log_entries.append((ts,level,text))
        try:
            self._log_text.configure(state="normal")
            pfx={"ok":"[OK]  ","warn":"[WRN] ","err":"[ERR] ","info":"[INF] ","threat":"[!!!] "}.get(level,"[   ] ")
            self._log_text.insert("end",f"[{ts}] {pfx}{text}\n",level)
            self._log_text.see("end"); self._log_text.configure(state="disabled")
        except: pass

    def _clear_logs(self):
        self._log_entries.clear()
        self._log_text.configure(state="normal"); self._log_text.delete("1.0","end"); self._log_text.configure(state="disabled")

    def _export_logs(self):
        p=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Log","*.txt")],
                                        initialfile=f"sonar_log_{datetime.now():%Y%m%d_%H%M%S}")
        if not p: return
        with open(p,"w",encoding="utf-8") as f:
            for ts,lvl,msg in self._log_entries: f.write(f"[{ts}] [{lvl.upper()}] {msg}\n")

    # ─── Файловые операции ────────────────────────────────────────────────
    def _add_files(self):
        paths=filedialog.askopenfilenames(title="Добавить файлы")
        added=0
        for p in paths:
            if p not in self._file_paths:
                self._file_paths.append(p); self._insert_pending(p); added+=1
        if added:
            msg=f"Добавлено {added} файл(ов). Итого: {len(self._file_paths)}"
            self._set_status(msg); self._log(msg,"info")

    def _add_folder(self):
        folder=filedialog.askdirectory(title="Добавить папку")
        if not folder: return
        added=0
        for root,dirs,files in os.walk(folder):
            dirs[:]=[d for d in dirs if not d.startswith('.')]
            for fn in files:
                p=os.path.join(root,fn)
                if p not in self._file_paths:
                    self._file_paths.append(p); self._insert_pending(p); added+=1
        msg=f"Добавлено из папки: {added} файл(ов)"
        self._set_status(msg); self._log(msg,"info")

    def _insert_pending(self,path):
        name=os.path.basename(path)
        size=_fmt(os.path.getsize(path)) if os.path.exists(path) else "—"
        self._tree.insert("","end",iid=path,values=("○",name,"—",size,"ожидание…"),tags=("pending",))

    def _start_scan(self):
        if self._running: messagebox.showinfo("Sonar","Подождите завершения."); return
        if not self._file_paths: messagebox.showinfo("Sonar","Добавьте файлы."); return
        self._running=True; self._results=[]
        self._prog.configure(maximum=len(self._file_paths),value=0)
        self._prog_lbl.configure(text="Сканирование…")
        self._prog_cnt.configure(text="")
        self._log(f"Сканирование {len(self._file_paths)} файлов…","info")
        threading.Thread(target=self._scan_worker,daemon=True).start()

    def _scan_worker(self):
        total=len(self._file_paths)
        for i,path in enumerate(self._file_paths):
            result=self._quick_check(path)
            self._results.append(result)
            self._q.put(("result",i+1,total,result))
        self._q.put(("done",total))

    def _quick_check(self,path) -> dict:
        """Быстрая проверка без C-ядра."""
        r={"path":path,"name":os.path.basename(path),"size":0,"type":"?","status":"ok","issues":[],"details":[]}
        try: r["size"]=os.stat(path).st_size
        except OSError as e: r["status"]="error"; r["issues"].append(str(e)); return r
        if r["size"]==0: r["status"]="warn"; r["issues"].append("Файл пустой"); return r
        r["type"]=self._detect_type(path)
        ext=Path(path).suffix.lower()
        try:
            if ext in('.zip','.docx','.xlsx','.pptx','.odt','.jar','.apk'):
                ok,d=self._check_zip(path)
            elif ext in('.tar','.tgz'): ok,d=self._check_tar(path)
            elif ext=='.gz': ok,d=self._check_gz(path)
            elif ext in('.jpg','.jpeg','.png'): ok,d=self._check_image(path)
            elif ext=='.pdf': ok,d=self._check_pdf(path)
            elif ext=='.wav': ok,d=self._check_wav(path)
            else: ok,d=self._check_generic(path)
            r["details"].append(d); r["status"]="ok" if ok else "error"
            if not ok: r["issues"].append(d)
        except Exception as e: r["details"].append(str(e)); r["status"]="error"
        return r

    def _start_deep(self):
        sel=self._tree.selection()
        if not sel:
            if not self._file_paths: messagebox.showinfo("Sonar","Добавьте файлы."); return
            # Многопоточный анализ всех файлов
            if self._running: return
            self._running=True
            paths=list(self._file_paths)
            self._results=[]
            self._prog.configure(maximum=len(paths)*10,value=0)
            self._prog_lbl.configure(text="🔬 Детальный анализ…")
            self._log(f"Многопоточный детальный анализ {len(paths)} файлов","info")
            threading.Thread(target=self._deep_all_worker,args=(paths,),daemon=True).start()
        else:
            self._start_deep_single(sel[0])

    def _start_deep_single(self,path):
        if self._running: messagebox.showinfo("Sonar","Подождите."); return
        self._running=True; self._prog.configure(maximum=10,value=0)
        self._prog_lbl.configure(text=f"🔬 {os.path.basename(path)}")
        self._log(f"Детальный анализ: {os.path.basename(path)}","info")
        threading.Thread(target=self._deep_worker,args=(path,),daemon=True).start()

    def _deep_worker(self,path):
        def prog(done,total,name): self._q.put(("dp",done,total,name))
        result=self._deep_analyze(path,prog)
        existing=next((r for r in self._results if r["path"]==path),None)
        if existing: existing.update(result)
        else: self._results.append(result)
        self._q.put(("deep_done",result))

    def _deep_all_worker(self,paths):
        """Многопоточный — пул из 4 воркеров."""
        q2=queue.Queue()
        for p in paths: q2.put(p)
        total=len(paths); done_count=[0]
        lock=threading.Lock()

        def worker():
            while True:
                try: path=q2.get(timeout=0.5)
                except: break
                r=self._deep_analyze(path,None)
                with lock:
                    self._results.append(r)
                    done_count[0]+=1
                    self._q.put(("result",done_count[0],total,r))
                q2.task_done()

        threads=[threading.Thread(target=worker,daemon=True) for _ in range(min(4,total))]
        for t in threads: t.start()
        for t in threads: t.join()
        self._q.put(("deep_all_done",total))

    def _deep_analyze(self,path,prog_cb):
        """Полный анализ: всё что умеет Sonar."""
        steps=["Базовая проверка","CRC-32","Энтропия","Нули/ASCII","Гистограмма",
               "Метаданные","Архив","Стеганография","Угрозы","Отчёт"]
        def step(i,n):
            if prog_cb: prog_cb(i+1,len(steps),n)
            time.sleep(0.03)

        r=self._quick_check(path); r["deep"]={}
        step(0,steps[0])
        step(1,steps[1])
        r["deep"]["crc32"]=f"{CORE.crc32(path):#010x}"
        step(2,steps[2])
        ent=CORE.entropy(path); r["deep"]["entropy"]=round(ent,4)
        r["deep"]["entropy_hint"]=("Очень высокая — сжатый/шифрованный" if ent>7.5 else
                                   "Высокая — сжатие/смешанный" if ent>6 else
                                   "Средняя — текст/структура" if ent>4 else "Низкая — текст/паттерн")
        step(3,steps[3])
        null_r=CORE.null_ratio(path); r["deep"]["null_ratio"]=round(null_r*100,2)
        r["deep"]["null_hint"]="Много нулей — повреждение?" if null_r>0.3 else "В норме"
        asc_r=CORE.ascii_ratio(path);  r["deep"]["ascii_ratio"]=round(asc_r*100,2)
        r["deep"]["content_class"]="текстовый" if asc_r>0.8 else "бинарный"
        step(4,steps[4])
        hist=CORE.histogram(path); total_b=sum(hist)
        top5=sorted(range(256),key=lambda i:hist[i],reverse=True)[:5]
        r["deep"]["histogram"]=hist
        r["deep"]["top_bytes"]=[{"byte":f"0x{b:02X}","char":chr(b) if 0x20<=b<=0x7E else "·",
                                  "count":hist[b],"pct":round(hist[b]/total_b*100,2) if total_b else 0}
                                 for b in top5]
        step(5,steps[5])
        r["deep"]["meta"]=META.read(path)
        step(6,steps[6])
        ext=Path(path).suffix.lower()
        if ext in('.zip','.docx','.xlsx','.pptx','.jar','.apk','.gz','.tar','.7z','.rar'):
            r["deep"]["archive"]=ARCH.analyze(path)
        step(7,steps[7])
        if ext in('.png','.jpg','.jpeg','.bmp','.webp') and HAS_PIL:
            r["deep"]["stego"]=STEGO.analyze(path)
        step(8,steps[8])
        try:
            with open(path,'rb') as f: first64k=f.read(65536)
        except: first64k=b''
        r["deep"]["threat"]=threat_scan(path,ent,null_r,first64k)
        step(9,steps[9])
        probs=list(r["issues"])
        if null_r>0.5: probs.append("Много нулевых байт")
        r["deep"]["verdict_problems"]=probs
        r["deep"]["c_backend"]=CORE.available
        return r

    def _scheduled_scan(self,paths,label):
        self._log(f"⏰ Планировщик: запуск «{label}»","info")
        for path in paths:
            if os.path.exists(path):
                r=self._quick_check(path)
                self._q.put(("sched_result",r,label))

    def _on_file_changed(self,path,event,old_size,new_size):
        msg=f"Файл изменён: {os.path.basename(path)} ({_fmt(old_size)}→{_fmt(new_size)})" if event=="modified" else f"Файл удалён: {os.path.basename(path)}"
        self._q.put(("monitor_event",path,event,msg))

    # ─── Очередь ──────────────────────────────────────────────────────────
    def _poll_queue(self):
        try:
            while True:
                msg=self._q.get_nowait(); tag=msg[0]
                if tag=="result":
                    _,done,total,r=msg; self._update_row(r)
                    self._prog.configure(value=done)
                    self._prog_lbl.configure(text=f"Проверено: {done}/{total}")
                elif tag=="done":
                    self._scan_done(msg[1])
                elif tag=="dp":
                    _,done,total,name=msg; self._prog.configure(value=done)
                    self._prog_lbl.configure(text=f"🔬 {name}"); self._set_status(name)
                elif tag=="deep_done":
                    r=msg[1]; self._update_row(r); self._running=False
                    self._prog_lbl.configure(text="Детальный анализ завершён")
                    self._set_status("Детальный анализ завершён")
                    self._render_details(r)
                    threat=r.get("deep",{}).get("threat",{})
                    if threat and threat.get("level")!="clean":
                        lvl="threat" if threat["level"]=="danger" else "warn"
                        self._log(f"УГРОЗА: {r['name']} — {threat['level'].upper()}",lvl)
                        for r2 in threat.get("reasons",[]): self._log(f"  {r2}",lvl)
                    else:
                        self._log(f"✓ {r['name']} — чисто","ok")
                elif tag=="deep_all_done":
                    n=msg[1]; self._running=False
                    ok=sum(1 for r in self._results if r.get("status")=="ok")
                    err=sum(1 for r in self._results if r.get("status")=="error")
                    self._prog_lbl.configure(text=f"Готово: {n} файлов")
                    self._prog_cnt.configure(text=f"✓{ok}  ✗{err}")
                    self._log(f"Многопоточный анализ завершён: {n} файлов, ошибок: {err}","ok" if not err else "warn")
                elif tag=="sched_result":
                    _,r,label=msg; self._update_row(r)
                    if r.get("status")!="ok":
                        self._log(f"⏰ [{label}] ПРОБЛЕМА: {r['name']}","warn")
                elif tag=="monitor_event":
                    _,path,event,msg2=msg; self._log(f"👁 {msg2}","warn")
                elif tag=="mic_result":
                    _,text,log_text,log_tag=msg
                    self._mic_card["sv"].set(text)
                    self._mic_card.get("btn_ref") and self._mic_card["btn_ref"].configure(state="normal")
                    self._dev_log_write(log_text,log_tag)
                    self._log(f"Микрофон: {log_text}",log_tag)
                    self._dev_tree.item(self._mic_node,text=f"🎤  Микрофон  [{'✓' if log_tag=='ok' else '⚠'} {text}]")
        except queue.Empty: pass
        self.after(80,self._poll_queue)

    def _update_row(self,r):
        icon={"ok":"✓","warn":"⚠","error":"✗"}.get(r.get("status","?"),"?")
        detail=(r.get("details",[])+r.get("issues",[])+["—"])[0]
        deep=r.get("deep",{})
        if deep:
            threat=deep.get("threat",{})
            lvl=threat.get("level","clean")
            pfx={"clean":"[🔬] ","suspicious":"⚠ ","danger":"🚨 "}[lvl]
            detail=pfx+detail
        tag={"ok":"ok","warn":"warn","error":"err"}.get(r.get("status",""),"pending")
        try:
            self._tree.item(r["path"],values=(icon,r["name"],r.get("type","?"),_fmt(r.get("size",0)),detail),tags=(tag,))
        except: pass

    def _scan_done(self,total):
        self._running=False
        ok=sum(1 for r in self._results if r.get("status")=="ok")
        warn=sum(1 for r in self._results if r.get("status")=="warn")
        err=sum(1 for r in self._results if r.get("status")=="error")
        self._prog_lbl.configure(text=f"Готово: {total}")
        self._prog_cnt.configure(text=f"✓{ok}  ⚠{warn}  ✗{err}"+(f"  Повреждено: {err}" if err else "  Всё исправно"))
        msg=f"Сканирование: {total} файлов. OK:{ok} WARN:{warn} ERR:{err}"
        self._set_status(msg); self._log(msg,"ok" if not err else "warn")

    def _clear(self):
        if self._running: messagebox.showinfo("Sonar","Подождите."); return
        self._file_paths.clear(); self._results.clear()
        for item in self._tree.get_children(): self._tree.delete(item)
        self._detail_text.configure(state="normal"); self._detail_text.delete("1.0","end"); self._detail_text.configure(state="disabled")
        self._prog_lbl.configure(text="Готов"); self._prog_cnt.configure(text=""); self._prog.configure(value=0)
        self._set_status("Список очищен"); self._log("Список очищен","info")

    def _show_details(self):
        sel=self._tree.selection()
        if not sel: return
        path=sel[0]
        res=next((r for r in self._results if r["path"]==path),None)
        if res: self._render_details(res)
        else: self._start_deep_single(path)

    def _export_report(self):
        if not self._results: messagebox.showinfo("Sonar","Нет данных."); return
        p=filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML отчёт","*.html"),("JSON","*.json"),("TXT","*.txt")],
            initialfile=f"sonar_report_{datetime.now():%Y%m%d_%H%M%S}")
        if not p: return
        if p.endswith(".html"):
            export_html(self._results,self._log_entries,p)
        elif p.endswith(".json"):
            safe=[{k:v for k,v in r.items() if k!="deep" or not isinstance(v,dict) or "histogram" not in v} for r in self._results]
            with open(p,"w",encoding="utf-8") as f: json.dump(safe,f,ensure_ascii=False,indent=2,default=str)
        else:
            with open(p,"w",encoding="utf-8") as f:
                f.write(f"SONAR v3.0 Report  {_dt()}\n{'='*70}\n\n")
                for r in self._results:
                    s={"ok":"OK","warn":"WARN","error":"DAMAGED"}.get(r.get("status"),"?")
                    f.write(f"[{s}] {r['path']}\n  Type:{r.get('type','?')}  Size:{_fmt(r.get('size',0))}\n")
                    for d in r.get("details",[]): f.write(f"  • {d}\n")
                    for i in r.get("issues",[]): f.write(f"  ! {i}\n")
                    deep=r.get("deep")
                    if deep:
                        f.write(f"  CRC:{deep.get('crc32')}  Entropy:{deep.get('entropy')}\n")
                        threat=deep.get("threat",{})
                        if threat.get("level")!="clean":
                            f.write(f"  THREAT:{threat.get('level','?').upper()}\n")
                            for r2 in threat.get("reasons",[]): f.write(f"    {r2}\n")
                    f.write("\n")
        self._log(f"Отчёт сохранён: {p}","ok")
        messagebox.showinfo("Sonar",f"Отчёт сохранён:\n{p}")

    # ─── Устройства ───────────────────────────────────────────────────────
    def _dev_log_write(self,text,tag="info"):
        self._dev_log.configure(state="normal")
        self._dev_log.insert("end",f"[{_ts()}]  {text}\n",tag)
        self._dev_log.see("end"); self._dev_log.configure(state="disabled")

    def _test_keyboard(self):
        self._kbd_active=True
        self._dev_log_write("Нажмите любую клавишу…","info")
        self._dev_tree.item(self._kbd_node,text="⌨  Клавиатура  [⏳ ожидание]")

    def _on_key(self,event):
        if self._kbd_active:
            self._kbd_active=False
            key=event.keysym
            self._dev_log_write(f"Клавиатура: «{key}» — OK","ok")
            self._log(f"Клавиатура: «{key}»","ok")
            self._dev_tree.item(self._kbd_node,text=f"⌨  Клавиатура  [✓ {key}]")

    def _test_mouse(self):
        self._mouse_active=True
        self._dev_log_write("Нажмите кнопку мыши или прокрутите…","info")
        self._dev_tree.item(self._mouse_node,text="🖱  Мышь  [⏳ ожидание]")

    def _on_click(self,event):
        if self._mouse_active:
            self._mouse_active=False
            btn={1:"Левая",2:"Средняя",3:"Правая"}.get(event.num,f"#{event.num}")
            self._dev_log_write(f"Мышь: {btn} кнопка ({event.x_root},{event.y_root}) — OK","ok")
            self._log(f"Мышь: {btn}","ok")
            self._dev_tree.item(self._mouse_node,text=f"🖱  Мышь  [✓ {btn}]")

    def _on_scroll(self,event):
        if self._mouse_active:
            self._mouse_active=False
            self._dev_log_write("Мышь: колесо прокрутки — OK","ok")
            self._dev_tree.item(self._mouse_node,text="🖱  Мышь  [✓ колесо]")

    def _test_mic(self):
        self._dev_log_write("Запись 2 сек…","info")
        self._dev_tree.item(self._mic_node,text="🎤  Микрофон  [⏳ запись]")
        threading.Thread(target=self._mic_worker,daemon=True).start()

    def _mic_worker(self):
        try:
            try:
                import sounddevice as sd,numpy as np
                rec=sd.rec(int(2*44100),samplerate=44100,channels=1,dtype='int16'); sd.wait()
                peak=int(np.abs(rec).max())
                self._q.put(("mic_result",f"✓ Пик:{peak}" if peak>50 else "⚠ Тихо",
                             f"Mic peak={peak}","ok" if peak>50 else "warn"))
                return
            except ImportError: pass
            if platform.system()=="Linux":
                r=subprocess.run(["arecord","-d","2","-f","S16_LE","-r","44100","-c","1","/tmp/sonar_mic.wav"],
                                  capture_output=True,timeout=5)
                if r.returncode==0 and os.path.exists("/tmp/sonar_mic.wav"):
                    sz=os.path.getsize("/tmp/sonar_mic.wav"); os.remove("/tmp/sonar_mic.wav")
                    self._q.put(("mic_result","✓ OK" if sz>1000 else "⚠ Тихо",f"arecord {sz}b","ok" if sz>1000 else "warn"))
                    return
            self._q.put(("mic_result","? Недоступно","pip install sounddevice","warn"))
        except Exception as e: self._q.put(("mic_result",f"✗ {e}",str(e),"err"))

    def _test_speakers(self):
        self._dev_log_write("Тест динамиков…","info")
        self._dev_tree.item(self._spk_node,text="🔊  Динамики  [⏳ тест]")
        _SpeakerWindow(self)

    # ─── Вспомогательные ──────────────────────────────────────────────────
    def _set_status(self,text):
        try:
            self._status_left.configure(text=f"  {text}")
            self._status_right.configure(text=f"{_ts()}  ")
        except: pass

    # ─── Быстрые форматные проверки ───────────────────────────────────────
    def _detect_type(self,path):
        SIGS={b'\x89PNG\r\n\x1a\n':'PNG',b'\xff\xd8\xff':'JPEG',b'GIF8':'GIF',
              b'%PDF':'PDF',b'PK\x03\x04':'ZIP/OOXML',b'Rar!':'RAR',b'\x1f\x8b':'GZIP',
              b'BZh':'BZIP2',b'\xfd7zXZ\x00':'XZ',b'7z\xbc\xaf':'7-ZIP',b'RIFF':'WAV/AVI',
              b'ID3':'MP3',b'\xff\xfb':'MP3',b'OggS':'OGG',b'\x1aE\xdf\xa3':'MKV/WEBM',
              b'fLaC':'FLAC',b'MZ':'EXE/DLL',b'\x7fELF':'ELF'}
        try:
            with open(path,'rb') as f: h=f.read(16)
            for sig,name in SIGS.items():
                if h[:len(sig)]==sig: return name
        except: pass
        return Path(path).suffix.upper().lstrip('.') or "File"

    def _check_zip(self,path):
        try:
            with zipfile.ZipFile(path,'r') as z:
                bad=z.testzip()
                return (False,f"Повреждён: {bad}") if bad else (True,f"ZIP OK · {len(z.namelist())} файлов")
        except zipfile.BadZipFile as e: return False,f"Bad ZIP: {e}"
        except Exception as e: return False,str(e)

    def _check_tar(self,path):
        try:
            with tarfile.open(path,'r:*') as t: return True,f"TAR OK · {len(t.getmembers())} объектов"
        except Exception as e: return False,str(e)

    def _check_gz(self,path):
        try:
            with gzip.open(path,'rb') as f:
                size=sum(len(c) for c in iter(lambda:f.read(65536),b''))
            return True,f"GZIP OK · {_fmt(size)}"
        except Exception as e: return False,str(e)

    def _check_image(self,path):
        ext=Path(path).suffix.lower()
        try:
            with open(path,'rb') as f: data=f.read()
            if ext=='.png':
                if data[:8]!=b'\x89PNG\r\n\x1a\n': return False,"Bad PNG sig"
                if not data.endswith(b'IEND\xaeB`\x82'): return False,"PNG обрезан"
                return True,f"PNG OK {_fmt(len(data))}"
            elif ext in('.jpg','.jpeg'):
                if data[:2]!=b'\xff\xd8': return False,"Bad JPEG sig"
                if data[-2:]!=b'\xff\xd9': return False,"JPEG обрезан"
                return True,f"JPEG OK {_fmt(len(data))}"
            return True,f"Изображение {_fmt(len(data))}"
        except Exception as e: return False,str(e)

    def _check_pdf(self,path):
        try:
            with open(path,'rb') as f:
                if not f.read(4).startswith(b'%PDF'): return False,"Not PDF"
                f.seek(-1024,2); tail=f.read()
            if b'%%EOF' not in tail and b'%EOF' not in tail: return False,"PDF обрезан"
            return True,"PDF OK"
        except Exception as e: return False,str(e)

    def _check_wav(self,path):
        try:
            with wave.open(path,'rb') as w:
                dur=w.getnframes()/w.getframerate() if w.getframerate() else 0
                return True,f"WAV {w.getnchannels()}ch {w.getframerate()}Hz {dur:.1f}s"
        except Exception as e: return False,str(e)

    def _check_generic(self,path):
        try:
            sz=os.path.getsize(path)
            with open(path,'rb') as f: f.read(512); f.seek(max(0,sz-512)); f.read(512)
            return True,f"OK {_fmt(sz)}"
        except Exception as e: return False,str(e)

    # ─── О программе ──────────────────────────────────────────────────────
    def _about(self):
        T=self.T
        win=tk.Toplevel(self); win.title("О программе — Sonar v3.0")
        win.geometry("500x460"); win.resizable(False,False); win.configure(bg=T["bg"]); win.grab_set()
        hdr=tk.Frame(win,bg=T["accent"],height=52); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr,text="  🔊 Sonar  v3.0",bg=T["accent"],fg=T["accent_fg"],
                 font=("Segoe UI",15,"bold")).pack(side="left",padx=10,pady=8)
        body=tk.Frame(win,bg=T["bg"]); body.pack(fill="both",expand=True,padx=16,pady=8)
        infos=[
            (f"C-ядро: {'активно' if CORE.available else 'Python fallback'}", T["log_ok"] if CORE.available else T["log_warn"]),
            (f"Вирусная БД: {len(VDB.signatures)} сигнатур | PIL: {'✓' if HAS_PIL else '✗'} | Mutagen: {'✓' if HAS_MUTAGEN else '✗'} | psutil: {'✓' if HAS_PSUTIL else '✗'}",T["fg2"]),
            ("",""),
            ("Возможности:",T["fg"]),
            ("  EXIF / ID3 / PDF / DOCX метаданные",T["fg2"]),
            ("  Рекурсивный анализ ZIP/RAR/7z",T["fg2"]),
            ("  Построчный diff текстовых файлов (ПКМ)",T["fg2"]),
            ("  Восстановление повреждённых заголовков",T["fg2"]),
            ("  LSB-стеганография + Chi² анализ",T["fg2"]),
            ("  Deep scan: 23 вирусных сигнатуры из JSON",T["fg2"]),
            ("  Сканирование процессов и автозагрузки",T["fg2"]),
            ("  Устройства: дисплей, батарея, сеть, BT, USB",T["fg2"]),
            ("  Real-time мониторинг файлов",T["fg2"]),
            ("  Планировщик по расписанию",T["fg2"]),
            ("  Многопоточный анализ (4 потока)",T["fg2"]),
            ("  Экспорт: TXT / JSON / HTML (Chart.js)",T["fg2"]),
            ("",""),
            ("F5 — сканировать  F6 — детальный разбор  ПКМ — меню",T["fg2"]),
        ]
        for txt,col in infos:
            if not txt: tk.Frame(body,bg=T["bg"],height=3).pack(fill="x")
            else: tk.Label(body,text=txt,bg=T["bg"],fg=col,font=("Consolas",8),anchor="w").pack(fill="x")
        sep=tk.Frame(win,bg=T["sep"],height=1); sep.pack(fill="x",padx=8)
        footer=tk.Frame(win,bg=T["bg"],height=50); footer.pack(fill="x",padx=12,pady=8)
        github_url="https://github.com"
        try:
            from PIL import Image,ImageTk
            icon_path=ASSETS_DIR/"github_icon.png"
            if icon_path.exists():
                img=Image.open(icon_path).resize((22,22),Image.LANCZOS)
                self._gh_icon=ImageTk.PhotoImage(img)
                tk.Button(footer,image=self._gh_icon,text="  GitHub",compound="left",
                          command=lambda:webbrowser.open(github_url),
                          bg=T["bg"],fg=T["fg"],relief="flat",cursor="hand2",
                          font=("Segoe UI",9,"underline")).pack(side="left")
            else: raise FileNotFoundError
        except:
            tk.Button(footer,text="⚫ GitHub →",command=lambda:webbrowser.open(github_url),
                      bg=T["bg"],fg="#6E40C9",relief="flat",cursor="hand2",
                      font=("Segoe UI",10,"underline")).pack(side="left")
        tk.Label(footer,text="© 2025 Sonar  MIT",bg=T["bg"],fg=T["fg2"],font=("Segoe UI",8)).pack(side="right")
        tk.Button(win,text="  OK  ",command=win.destroy,font=("Segoe UI",9),
                  bg=T["toolbar"],fg=T["fg"],relief="groove",cursor="hand2").pack(pady=(0,8))


def main():
    app=SonarApp()
    app.mainloop()

if __name__=="__main__":
    main()
