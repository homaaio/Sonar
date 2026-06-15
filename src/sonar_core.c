/*
 * sonar_core.c  —  C-ядро для глубокого анализа файлов (Sonar)
 * Версия 3.0 - Расширенное ядро с поддержкой безопасности и многоязычности
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

/* ─── Логирование ───────────────────────────────────────────────────────── */
static FILE* log_file = NULL;
static const char* log_path = "sonar_core.log";

static void log_message(const char* level, const char* format, ...) {
    if (!log_file) {
        log_file = fopen(log_path, "a");
    }
    if (log_file) {
        time_t now;
        time(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        fprintf(log_file, "[%s] [%s] ", time_str, level);
        
        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

EXPORT void core_log_info(const char* msg) {
    log_message("INFO", "%s", msg);
}

EXPORT void core_log_error(const char* msg) {
    log_message("ERROR", "%s", msg);
}

EXPORT void core_log_warning(const char* msg) {
    log_message("WARNING", "%s", msg);
}

/* ─── Многоязычная поддержка (расширенная) ─────────────────────────────── */
typedef enum {
    LANG_RU = 0,
    LANG_EN = 1,
    LANG_FR = 2,
    LANG_MAX
} Language;

static Language current_lang = LANG_EN;

static const char* const messages[LANG_MAX][50] = {
    [LANG_RU] = {
        "OK", "Ошибка", "Предупреждение", "Файл не найден",
        "Энтропия", "Нулевые байты", "ASCII-символы", "CRC-32",
        "Гистограмма", "Поиск сигнатуры", "Паттерн найден", "Паттернов: %lld",
        "ВЫСОКАЯ ЭНТРОПИЯ (7.5-8.0) - Возможно шифрование/сжатие",
        "СРЕДНЯЯ ЭНТРОПИЯ (6.0-7.5) - Смешанные данные",
        "НИЗКАЯ ЭНТРОПИЯ (4.0-6.0) - Структурированные данные",
        "ОЧЕНЬ НИЗКАЯ ЭНТРОПИЯ (<4.0) - Простой текст/паттерны",
        "Много нулевых байт - Возможно повреждение",
        "ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ", "БЕЗОПАСНЫЙ ФАЙЛ", "ВНИМАНИЕ: ПОТЕНЦИАЛЬНО ВРЕДОНОСНЫЙ",
        "Обнаружена подозрительная сигнатура", "Аномально высокая энтропия",
        "Подозрительные байтовые паттерны", "Файл может содержать shellcode",
        "Обнаружена PE-сигнатура (Windows executable)", "Обнаружен ELF (Linux executable)",
        "Подозрительные строки", "Возможное шифрование", "Потенциальный эксплойт"
    },
    [LANG_EN] = {
        "OK", "Error", "Warning", "File not found",
        "Entropy", "Zero bytes", "ASCII chars", "CRC-32",
        "Histogram", "Signature search", "Pattern found", "Patterns: %lld",
        "HIGH ENTROPY (7.5-8.0) - Possible encryption/compression",
        "MEDIUM ENTROPY (6.0-7.5) - Mixed data",
        "LOW ENTROPY (4.0-6.0) - Structured data",
        "VERY LOW ENTROPY (<4.0) - Plain text/patterns",
        "High zero byte ratio - Possible corruption",
        "SUSPICIOUS FILE", "SAFE FILE", "WARNING: POTENTIALLY MALICIOUS",
        "Suspicious signature detected", "Abnormally high entropy",
        "Suspicious byte patterns", "File may contain shellcode",
        "PE signature detected (Windows executable)", "ELF detected (Linux executable)",
        "Suspicious strings", "Possible encryption", "Potential exploit"
    },
    [LANG_FR] = {
        "OK", "Erreur", "Avertissement", "Fichier non trouvé",
        "Entropie", "Octets nuls", "Caractères ASCII", "CRC-32",
        "Histogramme", "Recherche signature", "Motif trouvé", "Motifs: %lld",
        "ENTROPIE ÉLEVÉE (7.5-8.0) - Chiffrement/compression possible",
        "ENTROPIE MOYENNE (6.0-7.5) - Données mixtes",
        "ENTROPIE FAIBLE (4.0-6.0) - Données structurées",
        "ENTROPIE TRÈS FAIBLE (<4.0) - Texte brut/patrons",
        "Taux de zéros élevé - Corruption possible",
        "FICHIER SUSPECT", "FICHIER SÛR", "ATTENTION: POTENTIELLEMENT MALVEILLANT",
        "Signature suspecte détectée", "Entropie anormalement élevée",
        "Motifs d'octets suspects", "Le fichier peut contenir du shellcode",
        "Signature PE détectée (exécutable Windows)", "ELF détecté (exécutable Linux)",
        "Chaînes suspectes", "Chiffrement possible", "Exploit potentiel"
    }
};

EXPORT void set_language(int lang) {
    if (lang >= 0 && lang < LANG_MAX) {
        current_lang = (Language)lang;
        log_message("INFO", "Language changed to %d", lang);
    }
}

EXPORT int get_language(void) {
    return (int)current_lang;
}

EXPORT const char* get_message(int msg_id) {
    if (msg_id >= 0 && msg_id < 50)
        return messages[current_lang][msg_id];
    return "???";
}

/* ─── Структура для результатов безопасности ───────────────────────────── */
typedef struct {
    int is_suspicious;
    int threat_level;  // 0-10
    char reasons[10][256];
    int reason_count;
} SecurityResult;

/* ─── Анализ безопасности файла ───────────────────────────────────────── */
static const uint8_t suspicious_signatures[][16] = {
    {0x4D, 0x5A},                    // MZ (PE executable)
    {0x7F, 0x45, 0x4C, 0x46},       // ELF
    {0xCA, 0xFE, 0xBA, 0xBE},       // Mach-O
    {0x25, 0x50, 0x44, 0x46},       // PDF (может содержать JavaScript)
    {0x3C, 0x3F, 0x78, 0x6D, 0x6C}, // <?xml (может содержать опасные макросы)
    {0x1F, 0x8B},                   // GZIP (может содержать скрытые файлы)
    {0x50, 0x4B, 0x03, 0x04},       // ZIP (может содержать вредоносные макросы)
};

static const char* signature_names[] = {
    "Windows Executable (PE)",
    "Linux Executable (ELF)",
    "macOS Executable (Mach-O)",
    "PDF (may contain JavaScript)",
    "XML (may contain malicious macros)",
    "GZIP Archive (may contain hidden files)",
    "ZIP Archive (may contain malicious macros)"
};

static const uint8_t suspicious_strings[][20] = {
    "CreateProcess", "WinExec", "ShellExecute", "WriteProcessMemory",
    "VirtualProtect", "LoadLibrary", "GetProcAddress", "URLDownloadToFile",
    "cmd.exe", "powershell", "wscript", "cscript", "rundll32",
    "reg add", "schtasks", "net user", "sc config"
};

static void check_suspicious_strings(const uint8_t* data, size_t size, SecurityResult* result) {
    for (int i = 0; i < sizeof(suspicious_strings) / sizeof(suspicious_strings[0]); i++) {
        const char* pattern = (const char*)suspicious_strings[i];
        size_t pattern_len = strlen(pattern);
        
        for (size_t j = 0; j + pattern_len <= size; j++) {
            if (memcmp(data + j, pattern, pattern_len) == 0) {
                snprintf(result->reasons[result->reason_count], 256,
                        "Found suspicious string: %s", pattern);
                result->reason_count++;
                result->is_suspicious = 1;
                result->threat_level += 3;
                break;
            }
        }
    }
}

static void check_byte_patterns(const uint8_t* data, size_t size, SecurityResult* result) {
    // Проверка на NOP-sled (shellcode pattern)
    int nop_count = 0;
    for (size_t i = 0; i + 1 < size; i++) {
        if (data[i] == 0x90 && data[i+1] == 0x90) {
            nop_count++;
            if (nop_count > 10) {
                snprintf(result->reasons[result->reason_count], 256,
                        "NOP-sled detected (possible shellcode)");
                result->reason_count++;
                result->is_suspicious = 1;
                result->threat_level += 5;
                break;
            }
        } else {
            nop_count = 0;
        }
    }
    
    // Проверка на INT 0x2E (syscall pattern)
    for (size_t i = 0; i + 1 < size; i++) {
        if (data[i] == 0xCD && data[i+1] == 0x2E) {
            snprintf(result->reasons[result->reason_count], 256,
                    "INT 0x2E syscall detected (possible exploit)");
            result->reason_count++;
            result->is_suspicious = 1;
            result->threat_level += 4;
            break;
        }
    }
}

/* ─── Основная функция проверки безопасности ──────────────────────────── */
EXPORT SecurityResult* scan_security(const char* path) {
    log_message("INFO", "Security scan started: %s", path);
    
    SecurityResult* result = (SecurityResult*)malloc(sizeof(SecurityResult));
    memset(result, 0, sizeof(SecurityResult));
    result->threat_level = 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        log_message("ERROR", "Cannot open file: %s", path);
        result->is_suspicious = -1;
        return result;
    }
    
    // Читаем первые 64KB для анализа
    uint8_t buffer[65536];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    
    if (bytes_read == 0) {
        log_message("WARNING", "Empty file: %s", path);
        result->is_suspicious = 0;
        return result;
    }
    
    // 1. Проверка сигнатур
    for (unsigned int i = 0; i < sizeof(suspicious_signatures) / sizeof(suspicious_signatures[0]); i++) {
        size_t sig_len = 0;
        for (int j = 0; j < 16 && suspicious_signatures[i][j] != 0; j++) sig_len++;
        
        if (memcmp(buffer, suspicious_signatures[i], sig_len) == 0) {
            snprintf(result->reasons[result->reason_count], 256,
                    "Suspicious signature: %s", signature_names[i]);
            result->reason_count++;
            result->is_suspicious = 1;
            result->threat_level += (i < 2) ? 8 : 4; // EXE/ELF более опасны
            log_message("WARNING", "Suspicious signature found in %s", path);
        }
    }
    
    // 2. Проверка энтропии
    double entropy = scan_entropy(path);
    if (entropy > 7.8) {
        snprintf(result->reasons[result->reason_count], 256,
                "Extremely high entropy (%.2f) - Strong encryption/packed", entropy);
        result->reason_count++;
        result->is_suspicious = 1;
        result->threat_level += 6;
        log_message("WARNING", "High entropy detected: %.2f in %s", entropy, path);
    } else if (entropy > 7.5) {
        snprintf(result->reasons[result->reason_count], 256,
                "High entropy (%.2f) - Possible encryption/compression", entropy);
        result->reason_count++;
        result->is_suspicious = 1;
        result->threat_level += 3;
    }
    
    // 3. Проверка нулевых байт
    double null_ratio = scan_nullratio(path);
    if (null_ratio > 0.5) {
        snprintf(result->reasons[result->reason_count], 256,
                "High zero byte ratio (%.1f%%) - Possible corruption or sparse file",
                null_ratio * 100);
        result->reason_count++;
        result->threat_level += 2;
    }
    
    // 4. Проверка подозрительных строк
    check_suspicious_strings(buffer, bytes_read, result);
    
    // 5. Проверка байтовых паттернов
    check_byte_patterns(buffer, bytes_read, result);
    
    // Ограничиваем уровень угрозы 10
    if (result->threat_level > 10) result->threat_level = 10;
    
    log_message("INFO", "Security scan completed for %s: threat_level=%d", 
                path, result->threat_level);
    
    return result;
}

EXPORT void free_security_result(SecurityResult* result) {
    if (result) free(result);
}

EXPORT int get_threat_level(SecurityResult* result) {
    return result ? result->threat_level : -1;
}

EXPORT int get_suspicious_count(SecurityResult* result) {
    return result ? result->reason_count : 0;
}

EXPORT const char* get_suspicious_reason(SecurityResult* result, int index) {
    if (result && index >= 0 && index < result->reason_count) {
        return result->reasons[index];
    }
    return "";
}

/* ─── Существующие функции (с добавлением логирования) ────────────────── */
EXPORT double scan_entropy(const char *path) {
    log_message("INFO", "Calculating entropy for: %s", path);
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_message("ERROR", "Cannot open file: %s", path);
        return -1.0;
    }

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
    
    log_message("INFO", "Entropy for %s: %.4f", path, entropy);
    return entropy;
}

EXPORT double scan_nullratio(const char *path) {
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

EXPORT double scan_ascii_ratio(const char *path) {
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

EXPORT uint32_t calc_crc32(const char *path) {
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

EXPORT int64_t scan_pattern(const char *path, uint32_t pattern) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    int64_t count = 0;
    uint8_t buf[65536 + 3];
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
        prev_tail = (total >= 3) ? 3 : total;
        memmove(buf, buf + total - prev_tail, prev_tail);
    }
    fclose(f);
    return count;
}

EXPORT void byte_histogram(const char *path, uint64_t *out_freq256) {
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

EXPORT int is_text_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    
    if (n == 0) return 0;
    
    int text_chars = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] >= 0x20 && buf[i] <= 0x7E) text_chars++;
        else if (buf[i] == 0x09 || buf[i] == 0x0A || buf[i] == 0x0D) text_chars++;
        else if (buf[i] == 0) return 0;
    }
    
    return (text_chars * 100 / n) >= 80 ? 1 : 0;
}

EXPORT const char* entropy_description(double entropy) {
    if (entropy > 7.5) return get_message(12);
    if (entropy > 6.0) return get_message(13);
    if (entropy > 4.0) return get_message(14);
    return get_message(15);
}

EXPORT const char* get_core_version(void) {
    return "3.0.0 (Security + Multi-language + Logging)";
}