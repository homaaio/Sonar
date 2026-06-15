/*
 * sonar_core.c  —  C-ядро для глубокого анализа файлов (Sonar)
 *
 * Компилируется как разделяемая библиотека (.so / .dll).
 * Python загружает через ctypes и вызывает функции напрямую.
 *
 * Что делает этот модуль:
 *   scan_entropy()    — считает энтропию Шеннона по байтам (признак шифрования/сжатия)
 *   scan_nullratio()  — доля нулевых байт (признак бинарного мусора / повреждения)
 *   find_magic()      — ищет известные сигнатуры в произвольном смещении внутри файла
 *   calc_crc32()      — CRC-32 всего файла для верификации целостности
 *   scan_ascii_ratio()— доля печатаемых ASCII-символов (текстовый vs бинарный)
 *   scan_pattern()    — подсчёт количества вхождений 4-байтного паттерна
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

/* ─── Энтропия Шеннона (бит/байт, 0..8) ─────────────────────────────── */
double scan_entropy(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1.0;

    uint64_t freq[256] = {0};
    uint64_t total = 0;
    uint8_t buf[65536];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++)
            freq[buf[i]]++;
        total += n;
    }
    fclose(f);

    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* ─── Доля нулевых байт (0.0 .. 1.0) ────────────────────────────────── */
double scan_nullratio(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1.0;

    uint64_t nulls = 0, total = 0;
    uint8_t buf[65536];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++)
            if (buf[i] == 0) nulls++;
        total += n;
    }
    fclose(f);
    return total == 0 ? 0.0 : (double)nulls / (double)total;
}

/* ─── Доля ASCII-печатаемых байт (0.0 .. 1.0) ───────────────────────── */
double scan_ascii_ratio(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1.0;

    uint64_t printable = 0, total = 0;
    uint8_t buf[65536];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++)
            if (buf[i] >= 0x20 && buf[i] <= 0x7E) printable++;
        total += n;
    }
    fclose(f);
    return total == 0 ? 0.0 : (double)printable / (double)total;
}

/* ─── CRC-32 (возвращает беззнаковое 32-бит целое) ──────────────────── */
uint32_t calc_crc32(const char *path) {
    /* Таблица CRC-32 (полином 0xEDB88320) */
    static uint32_t table[256];
    static int table_ready = 0;
    if (!table_ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        table_ready = 1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint32_t crc = 0xFFFFFFFFu;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        for (size_t i = 0; i < n; i++)
            crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    fclose(f);
    return crc ^ 0xFFFFFFFFu;
}

/* ─── Поиск 4-байтного паттерна (количество вхождений) ──────────────── */
int64_t scan_pattern(const char *path, uint32_t pattern) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    int64_t count = 0;
    uint8_t buf[65536 + 3];  /* +3 для перекрытия границ блоков */
    size_t prev_tail = 0;
    uint8_t pat[4];
    pat[0] = (pattern >> 24) & 0xFF;
    pat[1] = (pattern >> 16) & 0xFF;
    pat[2] = (pattern >>  8) & 0xFF;
    pat[3] =  pattern        & 0xFF;

    while (1) {
        size_t n = fread(buf + prev_tail, 1, 65536, f);
        if (n == 0) break;
        size_t total = prev_tail + n;
        for (size_t i = 0; i + 4 <= total; i++) {
            if (buf[i]   == pat[0] && buf[i+1] == pat[1] &&
                buf[i+2] == pat[2] && buf[i+3] == pat[3])
                count++;
        }
        /* Сохраняем хвост для перекрытия */
        prev_tail = (total >= 3) ? 3 : total;
        memmove(buf, buf + total - prev_tail, prev_tail);
    }
    fclose(f);
    return count;
}

/* ─── Поиск magic-байт в первых max_offset байтах ───────────────────── */
/*
 * magic    — указатель на байты сигнатуры
 * mlen     — длина сигнатуры (макс. 16)
 * max_off  — искать только в первых N байтах файла
 * Возвращает смещение первого вхождения или -1
 */
int64_t find_magic(const char *path,
                   const uint8_t *magic, int mlen, int64_t max_off) {
    if (mlen <= 0 || mlen > 16) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t buf[4096];
    int64_t offset = 0;
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i + (size_t)mlen <= n; i++) {
            if (memcmp(buf + i, magic, mlen) == 0) {
                int64_t pos = offset + (int64_t)i;
                fclose(f);
                return pos;
            }
        }
        offset += (int64_t)n;
        if (max_off > 0 && offset >= max_off) break;
    }
    fclose(f);
    return -1;
}

/* ─── Заполняет массив freq[256] частотами байт (для гистограммы) ───── */
void byte_histogram(const char *path, uint64_t *out_freq256) {
    memset(out_freq256, 0, 256 * sizeof(uint64_t));
    FILE *f = fopen(path, "rb");
    if (!f) return;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        for (size_t i = 0; i < n; i++)
            out_freq256[buf[i]]++;
    fclose(f);
}
