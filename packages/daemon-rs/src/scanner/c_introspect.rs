//! C-specific introspection for FORGE.
//!
//! Handles:
//! - `#include <X.h>` verification against C89/C99/C11/POSIX/GNU headers
//! - Bare function call verification against standard libc with arity check
//!
//! Distinct from cpp_introspect because C++ headers like `<cstdio>` and
//! `<algorithm>` are valid in C++ but hallucinations in pure C.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Known C headers — C89 + C99 + C11 + POSIX + common GNU/Linux.
///
/// Does NOT include C++-only headers like `<cstdio>`, `<algorithm>`,
/// `<vector>`, `<string>`, etc. Those are hallucinations in pure C code
/// (a common LLM failure mode: forgetting `cstdio` is C++-only).
static KNOWN_C_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s: HashSet<&'static str> = HashSet::new();
    // ─── C89 standard headers ───
    let c89 = [
        "assert.h", "ctype.h", "errno.h", "float.h", "limits.h",
        "locale.h", "math.h", "setjmp.h", "signal.h", "stdarg.h",
        "stddef.h", "stdio.h", "stdlib.h", "string.h", "time.h",
    ];
    for h in c89 { s.insert(h); }
    // ─── C99 additions ───
    let c99 = [
        "complex.h", "fenv.h", "inttypes.h", "iso646.h", "stdbool.h",
        "stdint.h", "tgmath.h", "wchar.h", "wctype.h",
    ];
    for h in c99 { s.insert(h); }
    // ─── C11 additions ───
    let c11 = [
        "stdalign.h", "stdatomic.h", "stdnoreturn.h", "threads.h",
        "uchar.h",
    ];
    for h in c11 { s.insert(h); }
    // ─── C23 additions (some toolchains) ───
    let c23 = ["stdbit.h", "stdckdint.h"];
    for h in c23 { s.insert(h); }
    // ─── POSIX headers (common subset) ───
    let posix = [
        "unistd.h", "fcntl.h", "sys/stat.h", "sys/types.h", "sys/wait.h",
        "sys/socket.h", "sys/ioctl.h", "sys/mman.h", "sys/time.h",
        "sys/resource.h", "sys/utsname.h", "sys/uio.h", "sys/select.h",
        "sys/poll.h", "sys/epoll.h", "sys/inotify.h", "sys/signalfd.h",
        "sys/timerfd.h", "sys/eventfd.h", "sys/ptrace.h", "sys/reg.h",
        "sys/user.h", "sys/param.h", "sys/syscall.h", "sys/sendfile.h",
        "arpa/inet.h", "netdb.h", "netinet/in.h", "netinet/tcp.h",
        "netinet/ip.h", "netinet/udp.h", "pthread.h", "semaphore.h",
        "dlfcn.h", "syslog.h", "dirent.h", "termios.h", "pty.h",
        "pwd.h", "grp.h", "glob.h", "ftw.h", "libgen.h",
        "poll.h", "utime.h", "utmp.h", "utmpx.h", "sys/shm.h",
        "sys/sem.h", "sys/msg.h", "sys/ipc.h", "sys/mount.h",
        "sys/reboot.h", "sys/swap.h", "sys/sysinfo.h", "sys/timeb.h",
        // BSD-specific
        "sys/socketvar.h", "sys/sysctl.h",
    ];
    for h in posix { s.insert(h); }
    // ─── GNU glibc extensions ───
    let gnu = [
        "getopt.h", "mntent.h", "stdio_ext.h", "gconv.h", "langinfo.h",
        "iconv.h", "locale.h", " monetary.h", "uchar.h", "strings.h",
        "error.h", "obstack.h", "argp.h", "argz.h", "envz.h",
        "fnmatch.h", "regexp.h", "regex.h", "wand/MagickWand.h",
    ];
    for h in gnu { s.insert(h); }
    s
});

/// Known C standard library functions with their arity (number of
/// required positional parameters — variadic functions record their
/// minimum required count).
///
/// Used to:
/// 1. Detect hallucinated non-standard functions (itoa, strrev, memdup)
/// 2. Verify call arity matches the function's signature
///
/// Arity format: minimum required args (variadic functions stop at the
/// fixed portion). For `printf` etc., arity is 1 (the format string).
static KNOWN_C_FUNCTIONS: Lazy<Vec<(&'static str, usize)>> = Lazy::new(|| {
    vec![
        // ─── <stdio.h> ───
        ("printf", 1), ("fprintf", 2), ("sprintf", 2), ("snprintf", 3),
        ("asprintf", 2), ("scanf", 1), ("fscanf", 2), ("sscanf", 2),
        ("vprintf", 1), ("vfprintf", 2), ("vsprintf", 2), ("vsnprintf", 3),
        ("fopen", 2), ("freopen", 3), ("fclose", 1), ("fflush", 1),
        ("fread", 4), ("fwrite", 4), ("fgetc", 1), ("fgets", 3),
        ("fputc", 2), ("fputs", 2), ("getc", 1), ("getchar", 0),
        ("gets", 1), ("putc", 2), ("putchar", 1), ("puts", 1),
        ("ungetc", 2), ("fseek", 3), ("ftell", 1), ("rewind", 1),
        ("fgetpos", 2), ("fsetpos", 2), ("feof", 1), ("ferror", 1),
        ("clearerr", 1), ("perror", 1), ("tmpfile", 0), ("tmpnam", 1),
        ("rename", 2), ("remove", 1), ("setbuf", 2), ("setvbuf", 4),
        // ─── <stdlib.h> ───
        ("atoi", 1), ("atol", 1), ("atoll", 1), ("atof", 1),
        ("strtol", 3), ("strtoll", 3), ("strtoul", 3), ("strtoull", 3),
        ("strtod", 2), ("strtof", 2), ("strtold", 2),
        ("rand", 0), ("srand", 1), ("malloc", 1), ("calloc", 2),
        ("realloc", 2), ("free", 1), ("aligned_alloc", 2),
        ("abort", 0), ("exit", 1), ("_Exit", 1), ("atexit", 1),
        ("at_quick_exit", 1), ("quick_exit", 1), ("getenv", 1),
        ("system", 1), ("abs", 1), ("labs", 1), ("llabs", 1),
        ("div", 2), ("ldiv", 2), ("lldiv", 2),
        ("qsort", 4), ("bsearch", 5), ("mblen", 2), ("mbtowc", 3),
        ("wctomb", 2), ("mbstowcs", 3), ("wcstombs", 3),
        // ─── <string.h> ───
        ("strlen", 1), ("strcpy", 2), ("strncpy", 3), ("strcat", 2),
        ("strncat", 3), ("strcmp", 2), ("strncmp", 3), ("strcoll", 2),
        ("strchr", 2), ("strrchr", 2), ("strstr", 2), ("strpbrk", 2),
        ("strspn", 2), ("strcspn", 2), ("strtok", 2), ("strtok_r", 3),
        ("strxfrm", 3), ("strerror", 1), ("strdup", 1), ("strndup", 2),
        ("memcpy", 3), ("memmove", 3), ("memset", 3), ("memcmp", 3),
        ("memchr", 3), ("memmem", 4),
        // ─── <ctype.h> ───
        ("isalnum", 1), ("isalpha", 1), ("isblank", 1), ("iscntrl", 1),
        ("isdigit", 1), ("isgraph", 1), ("islower", 1), ("isprint", 1),
        ("ispunct", 1), ("isspace", 1), ("isupper", 1), ("isxdigit", 1),
        ("tolower", 1), ("toupper", 1),
        // ─── <math.h> ───
        ("sqrt", 1), ("cbrt", 1), ("pow", 2), ("exp", 1), ("exp2", 1),
        ("expm1", 1), ("log", 1), ("log2", 1), ("log10", 1), ("log1p", 1),
        ("sin", 1), ("cos", 1), ("tan", 1), ("asin", 1), ("acos", 1),
        ("atan", 1), ("atan2", 2), ("sinh", 1), ("cosh", 1), ("tanh", 1),
        ("asinh", 1), ("acosh", 1), ("atanh", 1),
        ("floor", 1), ("ceil", 1), ("trunc", 1), ("round", 1),
        ("lround", 1), ("llround", 1), ("nearbyint", 1), ("rint", 1),
        ("fabs", 1), ("fmod", 2), ("fmax", 2), ("fmin", 2), ("fdim", 2),
        ("fma", 3), ("hypot", 2), ("copysign", 2),
        // ─── <time.h> ───
        ("time", 1), ("clock", 0), ("difftime", 2), ("mktime", 1),
        ("strftime", 4), ("ctime", 1), ("asctime", 1), ("gmtime", 1),
        ("localtime", 1), ("clock_gettime", 2), ("clock_settime", 2),
        // ─── <assert.h> ───
        ("assert", 1),
        // ─── <errno.h> ───
        // (constants only, no functions)
        // ─── <signal.h> ───
        ("signal", 2), ("raise", 1), ("kill", 2),
        // ─── <setjmp.h> ───
        ("setjmp", 1), ("longjmp", 2),
        // ─── <locale.h> ───
        ("setlocale", 2), ("localeconv", 0),
        // ─── <stddef.h> ───
        // (offsetof is a macro, no functions here)
        // ─── <stdint.h> ───
        // (no functions, only integer type typedefs)
        // ─── <stdbool.h> ───
        // (no functions, only bool macro)
        // ─── POSIX <unistd.h> ───
        ("read", 3), ("write", 3), ("open", 2), ("close", 1),
        ("lseek", 3), ("unlink", 1), ("rmdir", 1), ("chdir", 1),
        ("getcwd", 2), ("fork", 0), ("execvp", 2), ("execv", 2),
        ("execve", 3), ("dup", 1), ("dup2", 2), ("pipe", 1),
        ("access", 2), ("isatty", 1), ("fileno", 1),
        ("getpid", 0), ("getppid", 0), ("getuid", 0), ("geteuid", 0),
        ("getgid", 0), ("getegid", 0), ("sleep", 1), ("usleep", 1),
        ("alarm", 1),
        // ─── POSIX <sys/stat.h> ───
        ("stat", 2), ("fstat", 2), ("lstat", 2), ("mkdir", 2),
        ("chmod", 2), ("chown", 3), ("umask", 1),
        // ─── POSIX <pthread.h> ───
        ("pthread_create", 4), ("pthread_join", 2), ("pthread_exit", 1),
        ("pthread_mutex_init", 2), ("pthread_mutex_destroy", 1),
        ("pthread_mutex_lock", 1), ("pthread_mutex_unlock", 1),
        ("pthread_cond_init", 2), ("pthread_cond_destroy", 1),
        ("pthread_cond_wait", 2), ("pthread_cond_signal", 1),
        ("pthread_cond_broadcast", 1),
        // ─── POSIX <dirent.h> ───
        ("opendir", 1), ("readdir", 1), ("closedir", 1),
        ("rewinddir", 1), ("telldir", 1), ("seekdir", 2),
        // ─── POSIX <netdb.h> + <arpa/inet.h> ───
        ("gethostbyname", 1), ("gethostbyaddr", 3),
        ("getaddrinfo", 4), ("freeaddrinfo", 1),
        ("inet_addr", 1), ("inet_ntoa", 1), ("inet_pton", 3),
        ("inet_ntop", 4), ("htonl", 1), ("htons", 1),
        ("ntohl", 1), ("ntohs", 1),
        // ─── POSIX <socket.h> ───
        ("socket", 3), ("bind", 3), ("listen", 2), ("accept", 3),
        ("connect", 3), ("send", 4), ("recv", 4), ("sendto", 6),
        ("recvfrom", 6), ("setsockopt", 5), ("getsockopt", 5),
        ("shutdown", 2),
        // ─── POSIX <regex.h> ───
        ("regcomp", 3), ("regexec", 5), ("regfree", 1), ("regerror", 4),
    ]
});

/// Common C compiler builtins and macros that look like functions but
/// aren't user-defined — don't flag these as hallucinations.
static C_BUILTINS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // gcc/clang builtins
        "__builtin_expect", "__builtin_memcpy", "__builtin_memset",
        "__builtin_strcpy", "__builtin_strcmp", "__builtin_strlen",
        "__builtin_trap", "__builtin_unreachable", "__builtin_prefetch",
        "__builtin_clz", "__builtin_ctz", "__builtin_popcount",
        "__builtin_clzll", "__builtin_ctzll", "__builtin_popcountll",
        "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64",
        // C keywords (look like identifiers in regex)
        "if", "for", "while", "switch", "case", "default", "do",
        "return", "break", "continue", "goto", "sizeof", "_Alignof",
        "_Alignas", "_Static_assert", "_Generic", "_Noreturn",
        "_Thread_local", "_Atomic", "restrict", "inline", "extern",
        "static", "const", "volatile", "register", "auto",
        // C control-flow-like
        "true", "false", "NULL",
        // Common macros that look like functions
        "assert", "MIN", "MAX", "CLAMP",
    ]
    .iter()
    .copied()
    .collect()
});

/// Verify `#include <X.h>` directives against the known C headers list.
/// Flags headers not in the list, with levenshtein suggestions when close
/// to a real header.
pub fn verify_c_includes(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let include_re = Regex::new(
        r#"#include\s+(?:<([^>]+)>|"([^"]+)")"#
    ).unwrap();

    let mut checked: HashSet<String> = HashSet::new();
    let mut included: HashSet<String> = HashSet::new();

    for caps in include_re.captures_iter(content) {
        let header = caps.get(1).or_else(|| caps.get(2))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if header.is_empty() { continue; }
        if !checked.insert(header.to_string()) { continue; }
        included.insert(header.to_string());

        // Skip relative-path includes — likely project-local headers.
        if header.starts_with("./") || header.starts_with("../") || header.contains('\\') {
            continue;
        }

        if KNOWN_C_HEADERS.contains(header) { continue; }

        // Find closest known header by levenshtein on basename.
        let basename = header.rsplit('/').next().unwrap_or(header);
        let basename_no_ext = basename
            .trim_end_matches(".h")
            .trim_end_matches(".hpp");

        let closest = KNOWN_C_HEADERS.iter()
            .map(|known| {
                let known_base = known.rsplit('/').next().unwrap_or(known);
                let known_base_no_ext = known_base
                    .trim_end_matches(".h")
                    .trim_end_matches(".hpp");
                let dist = levenshtein_capped(basename_no_ext, known_base_no_ext, 4);
                (dist, known)
            })
            .filter(|(d, _)| *d <= 3)
            .min_by_key(|(d, _)| *d);

        match closest {
            Some((dist, suggestion)) => {
                // Distinguish C++ STL contamination explicitly — that's
                // a common LLM failure mode (using <cstdio> in C code).
                let cpp_note = if header.starts_with('c') && !header.contains('.') && !header.contains('/') {
                    let stl_root = &header[1..];
                    if KNOWN_C_HEADERS.contains(&format!("{}.h", stl_root).as_str()) {
                        Some(format!("{}.h", stl_root))
                    } else { None }
                } else { None };

                if let Some(c_equiv) = cpp_note {
                    warnings.push(format!(
                        "hallucinated-include: `<{}>` — C++ STL header used in C code; the C equivalent is `<{}>` (distance {})",
                        header, c_equiv, dist
                    ));
                } else {
                    warnings.push(format!(
                        "hallucinated-include: `<{}>` — not a standard C header. Did you mean `<{}>` (distance {})?",
                        header, suggestion, dist
                    ));
                }
            }
            None => {
                warnings.push(format!(
                    "hallucinated-include: `<{}>` — not a standard C header",
                    header
                ));
            }
        }
    }

    // Cross-check: symbols used in code vs. headers included.
    // Each C type/macro requires a specific header — if the header isn't
    // included, the symbol is effectively undefined at compile time.
    let symbol_warnings = verify_c_header_symbol_dependencies(content, &included);
    warnings.extend(symbol_warnings);

    warnings
}

/// Maps C type/macro names to the header(s) that define them. If a symbol
/// is used without at least one of its required headers included, flag it.
///
/// Based on C89/C99/C11/POSIX standards — fully general, not tied to any
/// specific codebase or hallucination sample.
fn verify_c_header_symbol_dependencies(
    content: &str,
    included: &HashSet<String>,
) -> Vec<String> {
    let stripped = strip_c_strings_and_comments(content);

    // Each entry: (symbol_regex_pattern, required_headers, kind)
    // required_headers is a list — at least ONE must be included.
    let deps: &[(&str, &[&str], &str)] = &[
        // ─── <stdint.h> types ───
        (r"\buint8_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\buint16_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\buint32_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\buint64_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\bint8_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\bint16_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\bint32_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\bint64_t\b", &["stdint.h", "sys/types.h"], "type"),
        (r"\buintptr_t\b", &["stdint.h"], "type"),
        (r"\bintptr_t\b", &["stdint.h"], "type"),
        // PRIu32, PRId64, etc. — printf format macros from <inttypes.h>
        (r#"\bPRI[d ioux X]{1,8}\b"#, &["inttypes.h"], "macro"),
        // ─── <stdbool.h> ───
        (r"\bbool\b", &["stdbool.h"], "type"),
        // ─── <limits.h> constants ───
        (r"\bINT_MAX\b", &["limits.h"], "macro"),
        (r"\bINT_MIN\b", &["limits.h"], "macro"),
        (r"\bUINT_MAX\b", &["limits.h"], "macro"),
        (r"\bLONG_MAX\b", &["limits.h"], "macro"),
        (r"\bLONG_MIN\b", &["limits.h"], "macro"),
        (r"\bULONG_MAX\b", &["limits.h"], "macro"),
        (r"\bLLONG_MAX\b", &["limits.h"], "macro"),
        (r"\bCHAR_BIT\b", &["limits.h"], "macro"),
        (r"\bPATH_MAX\b", &["limits.h", "sys/param.h"], "macro"),
        // ─── <stddef.h> ───
        (r"\bNULL\b", &["stddef.h", "stdio.h", "stdlib.h", "string.h", "time.h"], "macro"),
        (r"\bsize_t\b", &["stddef.h", "stdio.h", "stdlib.h", "string.h"], "type"),
        (r"\bptrdiff_t\b", &["stddef.h"], "type"),
        (r"\bwchar_t\b", &["stddef.h", "wchar.h", "wctype.h"], "type"),
        // ─── <errno.h> ───
        (r"\berrno\b", &["errno.h"], "macro"),
        // ─── <assert.h> ───
        (r"\bassert\s*\(", &["assert.h"], "macro"),
        // ─── <math.h> constants ───
        (r"\bM_PI\b", &["math.h"], "macro"),
        (r"\bM_E\b", &["math.h"], "macro"),
        (r"\bHUGE_VAL\b", &["math.h"], "macro"),
        (r"\bINFINITY\b", &["math.h"], "macro"),
        (r"\bNAN\b", &["math.h"], "macro"),
        // ─── POSIX <unistd.h> ───
        (r"\bSTDIN_FILENO\b", &["unistd.h"], "macro"),
        (r"\bSTDOUT_FILENO\b", &["unistd.h"], "macro"),
        (r"\bSTDERR_FILENO\b", &["unistd.h"], "macro"),
        (r"\bssize_t\b", &["sys/types.h", "unistd.h"], "type"),
        // ─── POSIX <sys/types.h> ───
        (r"\bpid_t\b", &["sys/types.h", "unistd.h"], "type"),
        (r"\buid_t\b", &["sys/types.h"], "type"),
        (r"\bgid_t\b", &["sys/types.h"], "type"),
        (r"\bmode_t\b", &["sys/types.h"], "type"),
        (r"\bdev_t\b", &["sys/types.h"], "type"),
        (r"\bino_t\b", &["sys/types.h"], "type"),
        (r"\bnlink_t\b", &["sys/types.h"], "type"),
        (r"\bblkcnt_t\b", &["sys/types.h"], "type"),
        (r"\bblksize_t\b", &["sys/types.h"], "type"),
        // ─── <pthread.h> ───
        (r"\bpthread_t\b", &["pthread.h", "sys/types.h"], "type"),
        (r"\bpthread_mutex_t\b", &["pthread.h"], "type"),
        (r"\bpthread_cond_t\b", &["pthread.h"], "type"),
    ];

    let mut warnings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (pattern, required, kind) in deps {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !re.is_match(&stripped) {
            continue;
        }
        // Check if any required header is included.
        let has_any = required.iter().any(|h| included.contains(*h));
        if has_any {
            continue;
        }

        // Extract a representative symbol name for the message (strip regex).
        let sym_display = pattern
            .trim_start_matches(r"\b")
            .trim_end_matches(r"\b")
            .trim_end_matches(r"\s*\(")
            .replace(r"\\b", "");

        let key = format!("{}:{}", sym_display, required.join(","));
        if !seen.insert(key) { continue; }

        let required_str = required
            .iter()
            .map(|h| format!("<{}>", h))
            .collect::<Vec<_>>()
            .join(" or ");

        // Include the actual include set in the message so baseline-diff
        // can distinguish baseline (no completion) from full content
        // (with hallucinated completion that adds a WRONG header). Without
        // this, the same warning would fire on both and baseline-diff
        // would cancel it out, missing the hallucination.
        let included_list = if included.is_empty() {
            "none".to_string()
        } else {
            let mut sorted: Vec<&String> = included.iter().collect();
            sorted.sort();
            sorted
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };

        warnings.push(format!(
            "hallucinated-include: `{}` {} used without required include ({}); have: [{}]",
            sym_display, kind, required_str, included_list
        ));
    }

    warnings
}

static FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-zA-Z_]\w*\s*\(([^)]*)\)\s*\{").unwrap()
});
static DECL_RE: Lazy<Regex> = Lazy::new(|| {
    // Captures the variable name in `type ... name [ = ... | ; | ( | [ ]`.
    //
    // `[\w\s*]*?` lazy middle replaces an earlier greedy
    // `(?:\s+\w+)*\s*\**\s*` form: the greedy inner `\w+` backtracked
    // one character and captured `y` from `HashEntry`, leaving the
    // actual variable name (`ret`, `errbuf`, `entry_count`) uncaptured.
    // The lazy middle + trailing anchor forces `(\w+)` to land on the
    // LAST identifier before the declaration terminator.
    Regex::new(
        r"\b(?:void|int|char|short|long|float|double|signed|unsigned|const|static|struct|union|enum|volatile|register|auto|extern|inline|size_t|ssize_t|ptrdiff_t|off_t|time_t|clock_t|pid_t|uid_t|gid_t|mode_t|uint\d+_t|int\d+_t|bool|FILE|fpos_t|jmp_buf|va_list|regex_t)\b[\w\s*]*?(\w+)\s*[=;(\[]"
    ).unwrap()
});
static FOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bfor\s*\(\s*(?:int|size_t|ssize_t|long|unsigned|char|short|ptrdiff_t|uint\d+_t|int\d+_t)\s+(\w+)").unwrap()
});
static IDENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z_]\w{2,})\b").unwrap()
});

/// Detect undefined variables in C source — catches LLM typos where a
/// defined identifier is misspelled (`widht` instead of `width`, etc.).
///
/// Tracks definitions from:
///   - function parameters: `int sum(int width, int height)` → defines `width`, `height`
///   - local variable declarations: `int total = 0;` → defines `total`
///   - `for` loop variables: `for (int i = 0; ...)` → defines `i`
///   - struct fields when accessed via `s.field` are not flagged (member access)
///
/// References that aren't definitions and aren't builtins/macros are flagged.
/// Conservative: requires name length >= 3 to avoid flagging short macro names.
pub fn verify_c_undefined_variables(content: &str) -> Vec<String> {
    use std::collections::HashSet;
    let stripped = strip_c_strings_and_comments(content);

    let mut defined: HashSet<String> = HashSet::new();
    let mut referenced: HashSet<String> = HashSet::new();

    // User-defined function names (definitions like `ret_type name(args) {`).
    // These count as "defined" so calls to them aren't flagged as undefined.
    let user_funcs = collect_user_defined_functions(&stripped);
    for name in &user_funcs {
        defined.insert(name.clone());
    }

    // Standard C library functions — every entry in KNOWN_C_FUNCTIONS is a
    // real libc symbol (string.h, ctype.h, stdio.h, regex.h, etc.). Treating
    // these as defined eliminates the dominant FP source: standard calls
    // like `fgets`, `tolower`, `strtok_r`, `strdup` flagged as hallucinated
    // because the static C_KW list below only covers the most common names.
    // Single source of truth: same table verify_c_function_calls uses for
    // arity verification.
    for (name, _) in KNOWN_C_FUNCTIONS.iter() {
        defined.insert((*name).to_string());
    }

    // Type names declared in this compilation unit — `typedef ... Name`,
    // `struct Name`, `union Name`, `enum Name`. References to user-defined
    // types are not hallucinations even when the type is defined in a
    // different snippet of the same response.
    //
    // Two patterns cover the common forms:
    //   - TAGGED_RE: `struct/union/enum Name` (also catches the tag in
    //     `typedef struct Tag { ... } Alias;`).
    //   - TYPEDEF_RE: the LAST identifier in a *single-statement* typedef
    //     (`typedef unsigned long ulong;`, `typedef int (*cmp_t)(...)`).
    //   - TYPEDEF_STRUCT_RE: the trailing alias on a multi-line struct/
    //     union/enum typedef (`} Alias;`). Without this, lazy `[^;]*?`
    //     stops at the first `;` inside the struct body and never reaches
    //     the alias.
    static TYPEDEF_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[ \t]*typedef\b[^{};]*?\b(\w+)\s*;").unwrap()
    });
    static TYPEDEF_STRUCT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\}\s*(\w+)\s*;").unwrap()
    });
    static TAGGED_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:struct|union|enum)\s+(\w+)").unwrap()
    });
    for line in stripped.lines() {
        if let Some(caps) = TYPEDEF_RE.captures(line) {
            if let Some(m) = caps.get(1) {
                defined.insert(m.as_str().to_string());
            }
        }
    }
    for caps in TYPEDEF_STRUCT_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }
    for caps in TAGGED_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }

    // C keywords + compiler builtins — never flagged.
    static C_KW: Lazy<HashSet<&str>> = Lazy::new(|| {
        [
            "auto", "break", "case", "char", "const", "continue", "default",
            "do", "double", "else", "enum", "extern", "float", "for", "goto",
            "if", "inline", "int", "long", "register", "restrict", "return",
            "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
            "union", "unsigned", "void", "volatile", "while",
            "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
            "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
            // Common macros / type names.
            "true", "false", "NULL", "bool", "size_t", "ssize_t", "ptrdiff_t",
            "int8_t", "int16_t", "int32_t", "int64_t",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t",
            "intptr_t", "uintptr_t",
            "pid_t", "uid_t", "gid_t", "mode_t", "time_t", "clock_t",
            "FILE", "fpos_t", "jmp_buf", "sig_atomic_t",
            "va_list",
            // POSIX regex.h types and constants (regex_t, REG_*).
            "regex_t", "regmatch_t", "regoff_t",
            "REG_EXTENDED", "REG_ICASE", "REG_NOSUB", "REG_NEWLINE",
            "REG_NOTBOL", "REG_NOTEOL",
            "REG_NOMATCH", "REG_BADBR", "REG_BADPAT", "REG_BADRPT",
            "REG_EBRACE", "REG_EBRACK", "REG_ECOLLATE", "REG_ECTYPE",
            "REG_EESCAPE", "REG_EPAREN", "REG_ERANGE", "REG_ESPACE",
            "REG_ESUBREG", "REG_ENOSYS",
            // C builtins / libc names commonly used as values.
            "errno", "stdin", "stdout", "stderr", "EXIT_SUCCESS", "EXIT_FAILURE",
            "INT_MAX", "INT_MIN", "UINT_MAX", "LONG_MAX", "LONG_MIN", "ULONG_MAX",
            "CHAR_BIT", "PATH_MAX",
            "EOF", "SEEK_SET", "SEEK_CUR", "SEEK_END",
            "NULL",
            // Common libc function names that also appear as identifiers.
            "printf", "fprintf", "sprintf", "snprintf", "scanf",
            "malloc", "calloc", "realloc", "free",
            "memcpy", "memmove", "memset", "memcmp",
            "strcpy", "strncpy", "strcat", "strncat",
            "strcmp", "strncmp", "strlen", "strchr", "strrchr", "strstr",
            "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
            "atoi", "atol", "atof", "strtol", "strtoul",
            "abs", "labs", "rand", "srand", "exit", "abort", "qsort",
            "sqrt", "pow", "floor", "ceil", "round", "fabs", "fmod",
            "sin", "cos", "tan", "atan", "atan2", "log", "log2", "log10", "exp",
            "assert",
            "main",
            // Preprocessor directives — never flagged.
            "define", "include", "ifdef", "ifndef", "endif", "elif", "pragma",
            "undef", "error", "warning", "line",
            // Common entrypoints.
            "argc", "argv",
        ]
        .iter()
        .copied()
        .collect()
    });

    // Function parameters: `name(args)` where args is `type name, type name, ...`.
    // We look for any function-like definition pattern and collect parameter names.
    for caps in FUNC_RE.captures_iter(&stripped) {
        if let Some(args) = caps.get(1) {
            for arg in args.as_str().split(',') {
                let arg = arg.trim();
                if arg.is_empty() || arg == "void" { continue; }
                // Last identifier in the param decl is the name.
                // `const char *src` → `src`. `int x` → `x`.
                if let Some(name) = arg.split_whitespace().last() {
                    let name = name.trim_start_matches('*').trim();
                    if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_alphabetic() || c == '_') {
                        // Array brackets at end: `int arr[]` → `arr`
                        let name = name.trim_end_matches("[]");
                        defined.insert(name.to_string());
                    }
                }
            }
        }
    }

    // Local variable declarations: `type name = ...;`, `type *name;`, etc.
    // Type is one or more type-keyword tokens (int, char, const, unsigned, etc.).
    // Allow any number of `*` between type and name (pointer declarations).
    for caps in DECL_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }

    // User-typed declarations: `TypeName *name` / `TypeName name` where
    // TypeName was introduced via typedef in this compilation unit.
    // DECL_RE only matches built-in type keywords, so without this pass
    // `HashTable *table = ...` and `HashEntry **entries = ...` slip through
    // and `table`/`entries` get flagged as hallucinated.
    // Anchor set `[=;,\[\(\)]` covers: array decls (`x[5]`), initialisers
    // (`x =`), parameters (`x,` / `x)`), and function-ptr decls (`x(`).
    static USER_TYPE_DECL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b([A-Z]\w*)\b[\w\s*]*?\*+\s*(\w+)\s*[=;,\[\(\)]").unwrap()
    });
    for caps in USER_TYPE_DECL_RE.captures_iter(&stripped) {
        // Only treat the leading identifier as a type if it's a known
        // typedef target (collected above) — prevents matching arbitrary
        // Capitalized function calls like `Regcomp(...)`.
        let type_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if defined.contains(type_name) {
            if let Some(m) = caps.get(2) {
                defined.insert(m.as_str().to_string());
            }
        }
    }

    // For loop variable: `for (int i = ...)` or `for (size_t i = ...)`.
    for caps in FOR_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }

    // Struct fields: `struct name { type field; ... };` — these are
    // field names, not variable names. Track and skip if referenced
    // via `.field`.
    // (Member access is filtered separately by the referenced pass.)

    // #define constants: `#define NAME value` — NAME is defined.
    static DEFINE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"#define\s+(\w+)").unwrap()
    });
    for caps in DEFINE_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }

    // Collect references: identifiers NOT preceded by `.` or `->`.
    let bytes = stripped.as_bytes();
    for caps in IDENT_RE.captures_iter(&stripped) {
        if let Some(m) = caps.get(1) {
            let pos = m.start();
            // Skip member access: preceded by `.` or `->`.
            let mut p = pos;
            while p > 0 && bytes[p - 1].is_ascii_whitespace() { p -= 1; }
            if p > 0 && bytes[p - 1] == b'.' { continue; }
            if p >= 2 && bytes[p - 1] == b'>' && bytes[p - 2] == b'-' { continue; }
            // Skip if preceded by another identifier char (part of a type decl).
            if p > 0 && (bytes[p - 1].is_ascii_alphanumeric() || bytes[p - 1] == b'_') {
                continue;
            }
            referenced.insert(m.as_str().to_string());
        }
    }

    let undefined: Vec<String> = referenced
        .into_iter()
        .filter(|n| !defined.contains(n) && !C_KW.contains(n.as_str()))
        .collect();
    let mut undefined = undefined;
    undefined.sort();
    undefined
}


static CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z_]\w*)\s*\(").unwrap()
});

/// Detect calls to functions that are neither:
///   (a) C standard library functions (with arity verification), nor
///   (b) user-defined functions in the same compilation unit, nor
///   (c) compiler builtins or macros.
///
/// This is a generalized rule — it doesn't hardcode specific "known
/// hallucinated" function names. Any function call that doesn't resolve
/// to one of the three categories above is flagged as hallucinated,
/// because the C standard requires either a declaration in scope or
/// a definition in the translation unit.
pub fn verify_c_function_calls(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // Strip string literals + comments so identifiers inside them aren't
    // treated as references.
    let stripped = strip_c_strings_and_comments(content);

    // Collect ALL user-defined function names from the source. A function
    // definition looks like: `[modifiers] ret_type name(args) {`.
    let user_defined = collect_user_defined_functions(&stripped);

    // Match `identifier(...)` patterns at call sites.

    // Build a lookup table for known libc functions.
    let known: std::collections::HashMap<&str, usize> =
        KNOWN_C_FUNCTIONS.iter().cloned().collect();

    let mut checked: HashSet<String> = HashSet::new();

    for caps in CALL_RE.captures_iter(&stripped) {
        let name = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };

        // Each function name only flagged once (first call site).
        if !checked.insert(name.to_string()) { continue; }

        // Skip compiler builtins and keywords.
        if C_BUILTINS.contains(name) { continue; }

        // Skip user-defined functions.
        if user_defined.contains(name) { continue; }

        // Find call site: position right after the opening paren.
        // Use the ORIGINAL content (not stripped) for arg extraction so
        // string-literal arguments like `perror("calloc")` are counted.
        // `strip_args_for_count` then collapses each string/char literal
        // within the extracted args to `_` so commas inside strings
        // (`strtok_r(s, ",.", &save)`) don't inflate the count.
        let call_start = caps.get(0).unwrap().end();
        let raw_args = extract_balanced_args(content, call_start);
        let arg_str = strip_args_for_count(&raw_args);

        // Case 1: Known libc function — verify arity.
        if let Some(&required_arity) = known.get(name) {
            let actual_arity = count_args(&arg_str);
            if actual_arity < required_arity {
                warnings.push(format!(
                    "hallucinated-parameter: `{}` — too few arguments (got {}, expected {})",
                    name, actual_arity, required_arity
                ));
            } else if actual_arity > required_arity && !is_variadic(name) {
                warnings.push(format!(
                    "hallucinated-parameter: `{}` — too many arguments (got {}, expected {})",
                    name, actual_arity, required_arity
                ));
            }
            continue;
        }

        // Case 2: Unknown function call — not in libc, not user-defined,
        // not a builtin. By the C standard, this is undefined behavior
        // (implicit declarations were removed in C99). Flag it.
        //
        // Conservative filter to avoid project-local helper functions
        // that aren't included in this scan:
        //   - Length >= 4 (skip short names that are often macros)
        //   - All lowercase + digits/underscore (libc convention)
        //   - Not preceded by `.` or `->` (struct member access)
        if name.len() >= 4 && looks_like_libc_call(name) {
            let pos = caps.get(1).unwrap().start();
            if is_member_access(&stripped, pos) {
                continue;
            }

            // Suggest closest libc function by levenshtein.
            let suggestion = KNOWN_C_FUNCTIONS.iter()
                .map(|(known_name, arity)| {
                    let dist = levenshtein_capped(name, known_name, 4);
                    (dist, known_name, *arity)
                })
                .filter(|(d, _, _)| *d <= 3)
                .min_by_key(|(d, _, _)| *d);

            match suggestion {
                Some((dist, sugg, _)) => {
                    warnings.push(format!(
                        "hallucinated-function: `{}` — not a standard C function and not defined in this translation unit. Did you mean `{}` (distance {})?",
                        name, sugg, dist
                    ));
                }
                None => {
                    warnings.push(format!(
                        "hallucinated-function: `{}` — not a standard C function and not defined in this translation unit",
                        name
                    ));
                }
            }
        }
    }

    warnings
}

static FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*\{").unwrap()
});

/// Collect all user-defined function names from C source.
///
/// A function definition is the pattern: `[modifiers] ret_type name(args) {`
/// where the open brace is on the same line or shortly after.
/// This excludes control-flow keywords (if/while/for/switch) by checking
/// the prefix token before `name`.
fn collect_user_defined_functions(content: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    // Match `name(args) {` — the `{` distinguishes a definition from a call.
    for caps in FUNC_DEF_RE.captures_iter(content) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() { continue; }
        // Skip control-flow keywords.
        if matches!(name, "if" | "while" | "for" | "switch" | "do" | "else") {
            continue;
        }
        // Check the prefix — must look like a return type declaration.
        let pos = caps.get(1).unwrap().start();
        let line_start = content[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let prefix = content[line_start..pos].trim();
        // Empty prefix means definition on its own line — likely a function.
        // Otherwise, prefix should be a type expression.
        if prefix.is_empty()
            || prefix.chars().all(|c| c.is_alphanumeric() || c == ' ' || c == '*' || c == '_')
        {
            out.insert(name.to_string());
        }
    }
    out
}

/// Check if the identifier at position `pos` is preceded by `.` or `->`
/// (struct/union member access — not a function call).
fn is_member_access(content: &str, pos: usize) -> bool {
    let bytes = content.as_bytes();
    let mut p = pos;
    while p > 0 && bytes[p - 1].is_ascii_whitespace() {
        p -= 1;
    }
    if p == 0 { return false; }
    // Direct `.`
    if bytes[p - 1] == b'.' { return true; }
    // `->` — check for `-` two positions back.
    if bytes[p - 1] == b'>' && p >= 2 && bytes[p - 2] == b'-' { return true; }
    false
}

/// Extract the balanced argument string starting just after the opening
/// paren at position `start`. Returns the raw text up to (but not
/// including) the matching close paren.
fn extract_balanced_args(content: &str, start: usize) -> String {
    let bytes = content.as_bytes();
    let mut depth = 1;
    let mut i = start;
    let n = bytes.len();
    while i < n && depth > 0 {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return content[start..i].to_string();
                }
            }
            _ => {}
        }
        i += 1;
    }
    content[start..].to_string()
}

/// Count top-level arguments in a call argument string. Splits by
/// commas at depth 0 (respecting nested parens/brackets).
fn count_args(arg_str: &str) -> usize {
    let trimmed = arg_str.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let mut depth = 0;
    let mut count = 1;
    for c in trimmed.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Replace each string/char literal in `arg_str` with a single `_` so
/// that commas inside string literals don't inflate `count_args`. Keeps
/// everything else (including identifier references) intact. Quotes
/// themselves are removed so the trimmed result is non-empty for any
/// non-empty argument list.
fn strip_args_for_count(arg_str: &str) -> String {
    let bytes = arg_str.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    while i < n {
        let b = bytes[i];
        if b == b'"' {
            out.push('_');
            i += 1;
            while i < n && bytes[i] != b'"' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < n { i += 2; continue; }
                i += 1;
            }
            if i < n && bytes[i] == b'"' { i += 1; }
            continue;
        }
        if b == b'\'' {
            out.push('_');
            i += 1;
            while i < n && bytes[i] != b'\'' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < n { i += 2; continue; }
                i += 1;
            }
            if i < n && bytes[i] == b'\'' { i += 1; }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Check if a function is variadic (accepts more args than its required arity).
fn is_variadic(name: &str) -> bool {
    matches!(
        name,
        "printf" | "fprintf" | "sprintf" | "snprintf" | "asprintf"
            | "scanf" | "fscanf" | "sscanf"
            | "vprintf" | "vfprintf" | "vsprintf" | "vsnprintf"
            | "open"  // open(path, flags, ...mode)
    )
}

/// Heuristic: does `name` look like a libc-style function name?
/// Libc names are lowercase, use underscores, e.g. `memcpy`, `strncpy`.
/// CamelCase names are typically project-local.
fn looks_like_libc_call(name: &str) -> bool {
    // All lowercase + underscores, no uppercase.
    name.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}

/// Levenshtein distance with early-exit when distance exceeds `max`.
/// Returns `max + 1` if it would exceed, useful for "within N" checks.
fn levenshtein_capped(a: &str, b: &str, max: usize) -> usize {
    if a == b { return 0; }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let m = a_bytes.len();
    let n = b_bytes.len();
    if m == 0 { return n; }
    if n == 0 { return m; }
    if m.abs_diff(n) > max { return max + 1; }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        // Track the minimum in this row; if it exceeds max, early-exit.
        let mut row_min = curr[0];
        for j in 1..=n {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
            if curr[j] < row_min {
                row_min = curr[j];
            }
        }
        if row_min > max {
            return max + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Strip string literals and comments from C source. Same approach as
/// GDScript: replaces contents with spaces to preserve offsets.
///
/// Also strips the contents of `#include <...>` angle brackets — the
/// header name inside isn't a code identifier.
fn strip_c_strings_and_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let b = bytes[i];
        // Line comment.
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            while i < n && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Block comment.
        if b == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 1 < n {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        // `#include <...>` — strip the angle-bracketed content. The
        // header name (e.g. `stdint.h`) isn't a code identifier.
        // Walk back to detect `#include` followed by whitespace before `<`.
        if b == b'<' {
            // Look back: skip whitespace, find "include" or "import",
            // then "#" before that.
            let mut p = out.len();
            while p > 0 && (out[p - 1] == b' ' || out[p - 1] == b'\t') { p -= 1; }
            let word_end = p;
            // Walk back over identifier chars.
            while p > 0 && (out[p - 1].is_ascii_alphabetic()) { p -= 1; }
            let word = String::from_utf8_lossy(&out[p..word_end]);
            if word == "include" || word == "import" {
                // Continue walking back past whitespace.
                let mut q = p;
                while q > 0 && (out[q - 1] == b' ' || out[q - 1] == b'\t') { q -= 1; }
                if q > 0 && out[q - 1] == b'#' {
                    // Yes — this `<` starts an include path. Strip until `>`.
                    while i < n && bytes[i] != b'>' && bytes[i] != b'\n' {
                        out.push(b' ');
                        i += 1;
                    }
                    if i < n && bytes[i] == b'>' {
                        out.push(b' ');
                        i += 1;
                    }
                    continue;
                }
            }
        }
        // String literal.
        if b == b'"' {
            out.push(b' ');
            i += 1;
            while i < n && bytes[i] != b'"' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(b' ');
                i += 1;
            }
            if i < n && bytes[i] == b'"' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Char literal.
        if b == b'\'' {
            out.push(b' ');
            i += 1;
            while i < n && bytes[i] != b'\'' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < n {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(b' ');
                i += 1;
            }
            if i < n && bytes[i] == b'\'' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_c_stl_contamination() {
        let src = "#include <cstdio>\nint main(void) { return 0; }\n";
        let w = verify_c_includes(src);
        assert!(w.iter().any(|s| s.contains("cstdio") && s.contains("stdio.h")));
    }

    #[test]
    fn detects_nonexistent_c_header() {
        let src = "#include <stdutility.h>\nint main(void) { return 0; }\n";
        let w = verify_c_includes(src);
        assert!(w.iter().any(|s| s.contains("stdutility")));
    }

    #[test]
    fn accepts_real_c_header() {
        let src = "#include <stdint.h>\nint main(void) { return 0; }\n";
        let w = verify_c_includes(src);
        assert!(w.is_empty(), "expected no warnings, got: {:?}", w);
    }

    #[test]
    fn detects_itoa_hallucination() {
        // itoa is NOT in libc — general rule catches it.
        let src = "int main(void) { char b[16]; itoa(42, b, 10); return 0; }\n";
        let w = verify_c_function_calls(src);
        assert!(w.iter().any(|s| s.contains("itoa") && s.contains("hallucinated-function")));
    }

    #[test]
    fn detects_strrev_hallucination() {
        // strrev is NOT in libc — general rule catches it.
        let src = "int main(void) { char s[] = \"hi\"; strrev(s); return 0; }\n";
        let w = verify_c_function_calls(src);
        assert!(w.iter().any(|s| s.contains("strrev")));
    }

    #[test]
    fn detects_memdup_hallucination() {
        // memdup is NOT in libc — general rule catches it.
        let src = "void *f(const void *s, size_t n) { return memdup(s, n); }\n";
        let w = verify_c_function_calls(src);
        assert!(w.iter().any(|s| s.contains("memdup")));
    }

    #[test]
    fn detects_wrong_arity_too_few() {
        // memcpy needs 3 args, only 2 supplied
        let src = "void f(char *d, const char *s) { memcpy(d, s); }\n";
        let w = verify_c_function_calls(src);
        assert!(w.iter().any(|s| s.contains("too few") && s.contains("memcpy")));
    }

    #[test]
    fn detects_wrong_arity_too_many() {
        // strcpy needs 2 args, 3 supplied
        let src = "void f(char *d, const char *s) { strcpy(d, s, 16); }\n";
        let w = verify_c_function_calls(src);
        assert!(w.iter().any(|s| s.contains("too many") && s.contains("strcpy")));
    }

    #[test]
    fn does_not_flag_user_defined_functions() {
        let src = r#"
            void my_helper(int x) { /* ... */ }
            int main(void) { my_helper(42); return 0; }
        "#;
        let w = verify_c_function_calls(src);
        // my_helper is defined above, should not be flagged.
        assert!(!w.iter().any(|s| s.contains("my_helper")), "got: {:?}", w);
    }

    #[test]
    fn does_not_flag_strings_inside_printf_format() {
        // "count=%s\n" is inside a string literal — should NOT be parsed.
        let src = r#"int main(void) { printf("count=%s\n", "hi"); return 0; }"#;
        let w = verify_c_function_calls(src);
        // printf is variadic, arity 1, called with 2 args → OK.
        assert!(w.is_empty(), "got: {:?}", w);
    }

    #[test]
    fn task16_repro_no_fps() {
        // Reproduces the task-16-c-strings false-positive pattern:
        // standard libc (regcomp, regexec, regfree, regerror, strtok_r),
        // POSIX regex types (regex_t) and constants (REG_NOSUB), and
        // common local declarations (size_t var, char buf[N]) must NOT
        // be flagged as hallucinated.
        let src = r#"
#include <stdio.h>
#include <string.h>
#include <regex.h>

typedef struct HashEntry {
    struct HashEntry *next;
} HashEntry;

typedef struct {
    HashEntry *buckets[256];
} HashTable;

HashEntry **get_entries(HashTable *t, size_t *count);

int main(int argc, char **argv) {
    regex_t regex;
    int ret = regcomp(&regex, "^[0-9]", REG_NOSUB);
    if (ret != 0) {
        char errbuf[256];
        regerror(ret, &regex, errbuf, sizeof(errbuf));
        fprintf(stderr, "regcomp failed: %s\n", errbuf);
        return 1;
    }
    HashTable *table = calloc(1, sizeof(HashTable));
    char *saveptr;
    char *tok = strtok_r(NULL, " ", &saveptr);
    size_t entry_count;
    HashEntry **entries = get_entries(table, &entry_count);
    regexec(&regex, tok, 0, NULL, 0);
    regfree(&regex);
    (void)entries; (void)argv; (void)argc;
    return 0;
}
"#;
        let w = verify_c_undefined_variables(src);
        eprintln!("TASK16 UNDEFINED: {:?}", w);
        // These are all real symbols or local declarations.
        for fp in &[
            "regcomp", "regexec", "regfree", "regerror", "strtok_r",
            "regex_t", "REG_NOSUB", "errbuf", "entry_count", "buckets",
        ] {
            assert!(
                !w.iter().any(|s| s == fp),
                "FP on `{}`: undefined={:?}",
                fp,
                w
            );
        }
    }
}
