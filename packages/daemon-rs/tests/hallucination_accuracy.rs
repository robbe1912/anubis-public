//! Hallucination scanner accuracy harness — TP / FP / Missed(FN) / TN.
//!
//! Calls `scan_response()` directly (no daemon — Rule 9 safe). Runs a fixed
//! set of multi-language snippets (Rust + Python + TypeScript + Go + C++)
//! through the full pipeline (L1 + L1.5 + FORGE + LSP gate + compiler gate
//! when `SKIP_COMPILER_GATES` is unset) and prints a per-language confusion
//! matrix + precision/recall.
//!
//! Intent: regression baseline. Today scanner may produce 0 TP on a given
//! language — that is OK, the harness itself is the deliverable. As detection
//! improves (lsp-fixer, compiler-gate hardening), numbers should climb.
//!
//! Run:
//!   cargo test --test hallucination_accuracy -- --nocapture
//!
//! NOTE: `SKIP_COMPILER_GATES` is forced unset at the top of the test so the
//! compiler gate always fires. Setting it in the shell has no effect.
//!
//! Cross-language note: cases set `language` explicitly so the per-language
//! FORGE runner + compiler verifier are selected deterministically. If a
//! toolchain is missing on the host (ruff / tsc / go / clang), the compiler
//! gate returns None and TP cases may land in MISSED. That is acceptable —
//! the harness documents which languages need toolchain installation.

use anubis_daemon::scanner::{scan_response, ScanContext};

/// One corpus case.
struct TestCase {
    name: &'static str,
    /// Raw snippet. Wrapped in a ```<language> fence before scanning so the
    /// markdown code-block extractor isolates it the way it would from a
    /// real LLM response.
    code: &'static str,
    /// language tag used both for the markdown fence and `ScanContext.language`
    /// (drives FORGE runner + compiler gate selection). One of:
    /// rust / python / typescript / go / cpp.
    language: &'static str,
    /// `true` = scanner SHOULD flag (hallucination present).
    /// `false` = scanner should stay silent (legit code / non-code).
    expected_hallucination: bool,
    /// Short rationale for triage when the matrix disagrees.
    note: &'static str,
}

// ─── Corpus ──────────────────────────────────────────────────────────

const CASES: &[TestCase] = &[
    // ════════════════════════════════════════════════════════════════════
    // RUST (12 cases — original corpus)
    // ════════════════════════════════════════════════════════════════════
    // ── TRUE POSITIVES (5) — scanner SHOULD flag ──────────────────────
    TestCase {
        name: "tp_hallucinated_type",
        code: "fn main() { let x: NonExistentType = todo!(); }",
        language: "rust",
        expected_hallucination: true,
        note: "fabricated type name; rustc E0412 / unresolved",
    },
    TestCase {
        name: "tp_hallucinated_method",
        code: "fn main() { let v = Vec::new(); v.fabricated_method(); }",
        language: "rust",
        expected_hallucination: true,
        note: "fabricated method on Vec; rustc E0599",
    },
    TestCase {
        name: "tp_hallucinated_import",
        code: "use std::collections::FakeCollection;\nfn main() {}",
        language: "rust",
        expected_hallucination: true,
        note: "invented std::collections item; rustc E0432",
    },
    TestCase {
        name: "tp_hallucinated_macro",
        code: "fn main() { println_fancy!(\"hello\"); }",
        language: "rust",
        expected_hallucination: true,
        note: "no such macro; rustc E0433 / cannot find macro",
    },
    TestCase {
        name: "tp_hallucinated_trait_method",
        code: "fn main() { let s = String::new(); s.nonexistent_fn(); }",
        language: "rust",
        expected_hallucination: true,
        note: "String has no method nonexistent_fn; rustc E0599",
    },
    // ── FALSE-POSITIVE RISKS (5) — scanner should NOT flag ────────────
    TestCase {
        name: "fp_risk_valid_vec_new",
        code: "fn main() { let v: Vec<u8> = Vec::new(); v.push(1); }",
        language: "rust",
        expected_hallucination: false,
        note: "stdlib Vec + push, fully valid",
    },
    TestCase {
        name: "fp_risk_valid_hashmap",
        code: "use std::collections::HashMap;\nfn main() { let m = HashMap::new(); }",
        language: "rust",
        expected_hallucination: false,
        note: "real import + ctor",
    },
    TestCase {
        name: "fp_risk_valid_string_len",
        code: "fn main() { let s = String::from(\"hi\"); println!(\"{}\", s.len()); }",
        language: "rust",
        expected_hallucination: false,
        note: "String::from + len + println all stdlib",
    },
    TestCase {
        name: "fp_risk_valid_format",
        code: "fn main() { let x = 42; println!(\"{}\", x); }",
        language: "rust",
        expected_hallucination: false,
        note: "trivial println",
    },
    TestCase {
        name: "fp_risk_valid_result_ret",
        code: "fn main() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }",
        language: "rust",
        expected_hallucination: false,
        note: "valid Result return + Box<dyn Error>",
    },
    // ── EDGE CASES (2) — scanner should NOT flag ──────────────────────
    TestCase {
        name: "edge_partial_code_no_main",
        code: "let x = 5;",
        language: "rust",
        expected_hallucination: false,
        note: "fragment, no main fn — too short / no API claims",
    },
    TestCase {
        name: "edge_prose_only",
        code: "You should use Vec::new() to create a vector.",
        language: "rust",
        expected_hallucination: false,
        note: "prose mention, no code block — extract_code_blocks_only yields nothing",
    },
    // ════════════════════════════════════════════════════════════════════
    // PYTHON (4 cases: 2 TP + 2 TN)
    // ════════════════════════════════════════════════════════════════════
    TestCase {
        name: "py_tp_nonexistent_module",
        code: "import nonexistent_module_xyz\n\nnonexistent_module_xyz.do_thing()",
        language: "python",
        expected_hallucination: true,
        note: "import of a module that does not exist on PyPI or stdlib; ruff F401 / pyright reportMissingImports",
    },
    TestCase {
        name: "py_tp_fabricated_dict_method",
        code: "obj = {\"a\": 1}\nobj.fabricated_method()",
        language: "python",
        expected_hallucination: true,
        note: "dict has no method fabricated_method; pyright reportGeneralTypeIssues / AttributeError at runtime",
    },
    TestCase {
        name: "py_tn_valid_stdlib_os",
        code: "import os\nprint(os.getcwd())",
        language: "python",
        expected_hallucination: false,
        note: "stdlib os.getcwd — fully valid",
    },
    TestCase {
        name: "py_tn_valid_list_append",
        code: "x = [1, 2, 3]\nx.append(4)",
        language: "python",
        expected_hallucination: false,
        note: "list.append is a real builtin method",
    },
    // ════════════════════════════════════════════════════════════════════
    // TYPESCRIPT (4 cases: 2 TP + 2 TN)
    // ════════════════════════════════════════════════════════════════════
    TestCase {
        name: "ts_tp_nonexistent_function",
        code: "const result = nonExistentFunction();",
        language: "typescript",
        expected_hallucination: true,
        note: "call to undefined free function; tsc TS2304 cannot find name",
    },
    TestCase {
        name: "ts_tp_fake_type",
        code: "const x: FakeType = {};",
        language: "typescript",
        expected_hallucination: true,
        note: "annotation with fabricated type; tsc TS2304 cannot find name 'FakeType'",
    },
    TestCase {
        name: "ts_tn_valid_array_push",
        code: "const arr: number[] = [1, 2, 3];\narr.push(4);",
        language: "typescript",
        expected_hallucination: false,
        note: "Array<number>.push — fully valid",
    },
    TestCase {
        name: "ts_tn_valid_console_log",
        code: "console.log('hello');",
        language: "typescript",
        expected_hallucination: false,
        note: "console is a lib.dom.d.ts / @types/node global",
    },
    // ════════════════════════════════════════════════════════════════════
    // GO (4 cases: 2 TP + 2 TN)
    // ════════════════════════════════════════════════════════════════════
    TestCase {
        name: "go_tp_fake_package",
        code: "package main\n\nimport \"fakepackagexyz\"\n\nfunc main() {\n\tfakepackagexyz.Function()\n}",
        language: "go",
        expected_hallucination: true,
        note: "import of a module that does not exist on the Go proxy; go vet / go build fails",
    },
    TestCase {
        name: "go_tp_fmt_nonexistent",
        code: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.NonExistentFunction()\n}",
        language: "go",
        expected_hallucination: true,
        note: "fmt has no function NonExistentFunction; go vet / compiler error",
    },
    TestCase {
        name: "go_tn_valid_fmt_println",
        code: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}",
        language: "go",
        expected_hallucination: false,
        note: "fmt.Println — stdlib valid",
    },
    TestCase {
        name: "go_tn_valid_strings_toupper",
        code: "package main\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n)\n\nfunc main() {\n\tfmt.Println(strings.ToUpper(\"hi\"))\n}",
        language: "go",
        expected_hallucination: false,
        note: "strings.ToUpper — stdlib valid",
    },
    // ════════════════════════════════════════════════════════════════════
    // C++ (2 cases: 1 TP + 1 TN)
    // ════════════════════════════════════════════════════════════════════
    TestCase {
        name: "cpp_tp_fake_std_function",
        code: "#include <iostream>\n\nint main() {\n\tstd::fake_function();\n\treturn 0;\n}",
        language: "cpp",
        expected_hallucination: true,
        note: "std has no function fake_function; clang reports no member named 'fake_function' in namespace 'std'",
    },
    TestCase {
        name: "cpp_tn_valid_cout",
        code: "#include <iostream>\n\nint main() {\n\tstd::cout << \"hello\" << std::endl;\n\treturn 0;\n}",
        language: "cpp",
        expected_hallucination: false,
        note: "std::cout + std::endl — fully valid iostream usage",
    },
];

// ─── Helpers ─────────────────────────────────────────────────────────

/// Build a ScanContext pointing at an empty tempdir. Empty API key means L3
/// (LLM judge) is skipped — deterministic layers (L1/L1.5/FORGE/LSP/compiler)
/// are what we measure here. `language` is set explicitly per-case so the
/// FORGE runner and compiler verifier route deterministically.
fn build_ctx(project_root: &std::path::Path, language: &str) -> ScanContext {
    ScanContext {
        project_root: project_root.to_string_lossy().to_string(),
        logic_model: "glm-4.7-flash".to_string(),
        llm_base_url: "https://api.z.ai/api/coding/paas/v4".to_string(),
        llm_api_key: String::new(), // empty → L3 cascade short-circuits
        llm_extra_headers: vec![],
        request_class: String::new(),
        language: language.to_string(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

/// Wrap a raw snippet in a language-tagged code fence. Edge case
/// `edge_prose_only` intentionally gets NO fence — it mimics a prose-only
/// LLM reply.
fn wrap(case: &TestCase) -> String {
    if case.name == "edge_prose_only" {
        return format!("{}\n", case.code);
    }
    format!("```{}\n{}\n```\n", case.language, case.code)
}

// ─── Test ────────────────────────────────────────────────────────────

#[tokio::test]
async fn hallucination_confusion_matrix() {
    // Compiler gate must fire for TP cases to flag. Strip any inherited
    // SKIP_COMPILER_GATES so we get the full pipeline regardless of shell env.
    std::env::remove_var("SKIP_COMPILER_GATES");

    let tmp = tempfile::tempdir().expect("tempdir");

    let mut tp = 0usize; // flagged + expected
    let mut fp = 0usize; // flagged + not expected
    let mut missed = 0usize; // not flagged + expected (false negative)
    let mut tn = 0usize; // not flagged + not expected

    // Per-language accumulators. Keyed by case.language.
    use std::collections::BTreeMap;
    let mut by_lang: BTreeMap<&'static str, [usize; 4]> = BTreeMap::new();
    // index meaning: [tp, fp, missed, tn]
    let mut by_lang_total_expected_true: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_lang_total_expected_false: BTreeMap<&'static str, usize> = BTreeMap::new();

    let total = CASES.len();
    println!("\n┌─ hallucination_accuracy: {} cases ─────────────", total);

    for case in CASES {
        let ctx = build_ctx(tmp.path(), case.language);
        let content = wrap(case);
        let started = std::time::Instant::now();
        let result = scan_response(&content, &ctx).await;
        let latency_ms = started.elapsed().as_millis();
        let flagged = !result.warnings.is_empty();

        let (bucket, emoji, idx) = match (flagged, case.expected_hallucination) {
            (true, true) => {
                tp += 1;
                ("TP ", "✓", 0usize)
            }
            (true, false) => {
                fp += 1;
                ("FP ", "✗", 1usize)
            }
            (false, true) => {
                missed += 1;
                ("MIS", "!", 2usize)
            }
            (false, false) => {
                tn += 1;
                ("TN ", "·", 3usize)
            }
        };

        let lang_row = by_lang.entry(case.language).or_insert([0usize; 4]);
        lang_row[idx] += 1;
        if case.expected_hallucination {
            *by_lang_total_expected_true.entry(case.language).or_insert(0) += 1;
        } else {
            *by_lang_total_expected_false.entry(case.language).or_insert(0) += 1;
        }

        println!(
            "{} [{}] {:<32} lang={:<11} flagged={:<5} latency_ms={:<5} warns={}",
            emoji,
            bucket,
            case.name,
            case.language,
            flagged,
            latency_ms,
            result.warnings.len()
        );
        if flagged {
            for w in &result.warnings {
                println!("      • {}", w);
            }
        }
        if !result.details.is_empty() {
            println!("      details: {}", result.details.join("; "));
        }
        println!("      note: {}", case.note);
    }

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64 * 100.0
    } else {
        0.0
    };
    let recall = if tp + missed > 0 {
        tp as f64 / (tp + missed) as f64 * 100.0
    } else {
        0.0
    };
    let accuracy = if total > 0 {
        (tp + tn) as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let expected_true_total: usize = by_lang_total_expected_true.values().sum();
    let expected_false_total: usize = by_lang_total_expected_false.values().sum();

    println!("└──────────────────────────────────────────────────");
    println!();
    println!("=== PER-LANGUAGE CONFUSION MATRIX ===");
    println!(
        "{:<12} {:>4} {:>4} {:>4} {:>4} {:>8} {:>8} {:>8}",
        "language", "TP", "FP", "MIS", "TN", "prec%", "rec%", "acc%"
    );
    for (lang, row) in by_lang.iter() {
        let (l_tp, l_fp, l_missed, l_tn) = (row[0], row[1], row[2], row[3]);
        let l_total = l_tp + l_fp + l_missed + l_tn;
        let l_prec = if l_tp + l_fp > 0 {
            l_tp as f64 / (l_tp + l_fp) as f64 * 100.0
        } else {
            0.0
        };
        let l_rec = if l_tp + l_missed > 0 {
            l_tp as f64 / (l_tp + l_missed) as f64 * 100.0
        } else {
            0.0
        };
        let l_acc = if l_total > 0 {
            (l_tp + l_tn) as f64 / l_total as f64 * 100.0
        } else {
            0.0
        };
        println!(
            "{:<12} {:>4} {:>4} {:>4} {:>4} {:>7.1}% {:>7.1}% {:>7.1}%",
            lang, l_tp, l_fp, l_missed, l_tn, l_prec, l_rec, l_acc
        );
    }
    println!();
    println!("=== AGGREGATE CONFUSION MATRIX ({} cases) ===", total);
    println!("True Positives:  {}/{} expected-flagged", tp, expected_true_total);
    println!("False Positives: {}/{} expected-clean", fp, expected_false_total);
    println!("Missed (FN):     {}/{} expected-flagged", missed, expected_true_total);
    println!("True Negatives:  {}/{} expected-clean", tn, expected_false_total);
    println!();
    println!("Precision:       {:.1}%  (TP / (TP + FP))", precision);
    println!("Recall:          {:.1}%  (TP / (TP + FN))", recall);
    println!("Accuracy:        {:.1}%  ((TP + TN) / N)", accuracy);

    // ─── Assertions ──────────────────────────────────────────────────
    // Soft floor: harness must execute end-to-end and produce a sane matrix.
    // Hard floor: at least one case landed in some bucket (sanity check).
    assert!(tp + fp + missed + tn == total, "bucket sum must equal total");
    // Per the brief: don't assert FP=0 or recall > 0 yet — scanner tuning is
    // tracked separately (lsp-fixer task #2). Harness is the deliverable.
    let _ = (precision, recall, accuracy); // also surfaceable in asserts later
}
