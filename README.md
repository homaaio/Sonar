# Sonar

A desktop file and device diagnostics tool built with Python/Tkinter, with an
optional C extension for fast entropy, CRC32, histogram, and LSB-steganography
calculations.

## Features

- **File analysis** — type detection, EXIF/ID3/DOCX/PDF metadata, recursive
  archive structure, entropy, CRC32, byte histograms.
- **File comparison** — line-by-line diff with highlighting (right-click a
  file → *Compare*).
- **Header/footer repair** — detects and fixes corrupted file signatures for
  common formats (JPEG, PNG, GIF, PDF, ZIP family, GZIP, BMP, MP3, WAV).
  ZIP repairs are verified by actually re-opening the archive afterward;
  if the result still isn't a valid ZIP, Sonar reports failure instead of
  a false "fixed" message.
- **Steganography** — LSB randomness analysis on images.
- **Deep scan** — signature-based virus/threat scan against a JSON database.
- **Device tests** — keyboard, mouse, microphone, speakers, display, battery,
  Wi-Fi/network, Bluetooth, USB.
- **Monitoring** — real-time file-change watching.
- **Scheduler** — automatic recurring scans.
- **Multi-threaded** analysis pool.
- **Drag & drop** file/folder input.
- **Export** — TXT, JSON, or a plain (unstyled) HTML report.
- **Light theme** by default.

## Project layout

```
project-root/
├── src/
│   └── sonar.py        ← run this
└── Assets/
    ├── keyboard.png
    ├── mouse.png
    ├── microphone.png
    ├── speakers.png
    ├── display.png
    ├── battery.png
    ├── network.png
    ├── bluetooth.png
    ├── usb.png
    └── github_icon.png  (optional, used in the About dialog)
```

`sonar.py` looks for `Assets/` one directory above itself, so the two folders
must be siblings as shown above. Any device tile without a matching image
falls back to an emoji icon automatically — nothing breaks if `Assets/` is
empty or `Pillow` isn't installed, you just won't see custom pictures.

Image requirements: PNG/JPEG/WEBP, any size (auto-resized to ~44×44 in the
tile). Square source images look best.

## Requirements

- Python 3.9+
- `tkinter` (bundled on Windows/macOS; on Linux install separately, e.g.
  `sudo apt install python3-tk`)

Optional, for extra features (the app runs fine without them and disables
the related feature instead):

| Package   | Used for                                  |
|-----------|--------------------------------------------|
| `Pillow`  | image metadata/thumbnails, device icons    |
| `mutagen` | MP3/FLAC/OGG audio metadata                |
| `psutil`  | process/autorun inspection                 |

Install with:
```bash
pip install Pillow mutagen psutil
```

A C compiler (`gcc`) is optional too — if present, Sonar compiles a small
helper library on first run for faster entropy/CRC32/histogram/LSB
calculations; otherwise it transparently falls back to pure-Python
implementations.

## Running

```bash
cd src
python3 sonar.py
```

## Virus signatures

Deep scan reads `src/virus_db/signatures.json`. If the file is missing, deep
scan simply reports zero signatures instead of failing.

## Notes on the repair tool

The repair tool only ever rewrites bytes it can be certain are wrong (the
fixed magic signature of a known format, or a missing trailing footer). For
ZIP-family files specifically, it no longer guesses at version/flag/method
bytes that legitimately vary between valid archives — it verifies the
repaired file actually opens and passes a CRC check before reporting
success, and clearly reports failure (instead of a false "repaired" message)
when the underlying data can't be reconstructed.
