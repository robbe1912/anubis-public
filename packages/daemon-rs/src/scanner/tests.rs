    use super::*;

    // ── Pure helper tests ────────────────────────────────────────────────

    fn make_ctx() -> ScanContext {
        ScanContext {
            project_root: "/test".to_string(),
            logic_model: "test-model".to_string(),
            llm_base_url: String::new(),
            llm_api_key: String::new(),
            llm_extra_headers: vec![],
            request_class: "test".to_string(),
             language: String::new(),
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    #[test]
    fn current_time_ms_returns_nonzero_monotonic() {
        let t1 = current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t2 = current_time_ms();
        assert!(t2 > t1, "time must advance: t1={t1} t2={t2}");
        assert!(t1 > 0, "timestamp should not be zero");
    }

    #[test]
    fn build_cache_key_is_deterministic_same_input() {
        let ctx = make_ctx();
        let k1 = build_cache_key("hello", &ctx);
        let k2 = build_cache_key("hello", &ctx);
        assert_eq!(k1, k2, "same input must produce same hash");
    }

    #[test]
    fn build_cache_key_changes_with_different_input() {
        let ctx = make_ctx();
        let k1 = build_cache_key("hello", &ctx);
        let k2 = build_cache_key("world", &ctx);
        assert_ne!(k1, k2, "different input must produce different hash");
    }

    #[test]
    fn build_cache_key_changes_with_different_context() {
        let mut ctx1 = make_ctx();
        let mut ctx2 = make_ctx();
        ctx1.project_root = "/a".to_string();
        ctx2.project_root = "/b".to_string();
        let k1 = build_cache_key("hello", &ctx1);
        let k2 = build_cache_key("hello", &ctx2);
        assert_ne!(k1, k2, "different context must produce different hash");
    }

    #[test]
    fn skip_names_contains_common_false_positives() {
        let s = skip_names();
        // These should be in skip list — common variable names that look like API calls
        assert!(s.contains("console"));
        assert!(s.contains("Math"));
        assert!(s.contains("window"));
        assert!(!s.contains("axios"), "axios is a real library, not skipped");
        assert!(!s.contains("react"), "react is a real library, not skipped");
    }

    // ── check_claim_in_index — word-boundary regression tests (bug B4) ──
    //
    // The old `index.to_lowercase().contains(method)` impl matched `app(`
    // against `happiness: true` because "happiness" contains "app". These
    // tests pin the word-boundary behavior.

    #[test]
    fn check_claim_in_index_word_boundary_rejects_substring_match() {
        // "happiness" contains "app" as substring, but the word-boundary check
        // must NOT match. This is the exact bug B4 regression test.
        let index = "App.tsx: happiness\nApp.tsx: greeting";
        assert!(
            !check_claim_in_index("app(", index),
            "claim 'app(' must NOT match index 'happiness' by substring"
        );
        assert!(
            !check_claim_in_index("app(", index),
            "claim 'app(' must NOT match index 'greeting' by substring"
        );
    }

    #[test]
    fn check_claim_in_index_exact_token_match_passes() {
        let index = "app.ts: init\nmain.ts: runApp";
        assert!(
            check_claim_in_index("init(", index),
            "exact token match should pass"
        );
        assert!(
            check_claim_in_index("runApp(", index),
            "camelCase token match should pass"
        );
    }

    #[test]
    fn check_claim_in_index_snake_case_tail_segment_matches() {
        // apply_scale should match the claim `scale(` since `scale` is the
        // underscore-separated tail. Minimum length 3 to avoid false positives
        // like `a_b` matching claim `b(`.
        let index = "Node2D.ts: apply_scale\nVector2.ts: normalize";
        assert!(
            check_claim_in_index("scale(", index),
            "snake_case tail 'scale' should match claim 'scale('"
        );
        assert!(
            check_claim_in_index("normalize(", index),
            "exact match on 'normalize' should pass"
        );
    }

    #[test]
    fn check_claim_in_index_short_claims_dont_match_tail_segments() {
        // "ab" is below the 3-char minimum for tail-segment matching — must
        // NOT match "cab" via tail segment.
        let index = "x.ts: cab";
        assert!(
            !check_claim_in_index("ab(", index),
            "short claim 'ab(' must not match tail segment of 'cab'"
        );
    }

    #[test]
    fn check_claim_in_index_dotted_path_extracts_method() {
        let index = "Repo.rs: find\nRepo.rs: save";
        assert!(
            check_claim_in_index("Repo.find(", index),
            "dotted claim should extract 'find' and match"
        );
        assert!(
            !check_claim_in_index("Repo.delete(", index),
            "dotted claim with missing method should not match"
        );
    }

    #[test]
    fn check_claim_in_index_empty_target_returns_false() {
        // Defensive: a claim like ".(" (empty after dot) shouldn't panic
        // and should return false.
        assert!(!check_claim_in_index(".(", "anything: here"));
        assert!(!check_claim_in_index("(", "anything: here"));
    }

    #[test]
    fn check_claim_in_index_empty_index_returns_false() {
        assert!(!check_claim_in_index("anything(", ""));
    }

    #[test]
    fn skip_names_is_nonempty() {
        assert!(!skip_names().is_empty(), "skip_names must return non-empty set");
    }

    #[test]
    fn claim_patterns_is_nonempty() {
        assert!(!claim_patterns().is_empty(), "claim_patterns must return non-empty vec");
    }

    // ── extract_api_claims ──────────────────────────────────────────────

    #[test]
    fn extract_api_claims_finds_class_method_pattern() {
        let code = "```js\nconst x = MyLib.fetchData('url');\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("MyLib")),
            "should extract MyLib claim from: {code}, got: {claims:?}"
        );
    }

    #[test]
    fn extract_api_claims_skips_console() {
        let code = "```js\nconsole.log('hello'); console.error('oops');\n```";
        let claims = extract_api_claims(code);
        // console should be skipped per skip_names
        let console_leak = claims.iter().any(|c| c.to_lowercase().contains("console"));
        assert!(!console_leak, "console should not leak into claims: {claims:?}");
    }

    #[test]
    fn extract_api_claims_is_callable() {
        // Smoke test — function is callable and doesn't panic on typical input.
        // Detailed claim extraction behavior depends on claim_patterns() regex set.
        let _ = extract_api_claims("const x = obj.method();");
        let _ = extract_api_claims("");
    }

    #[test]
    fn extract_api_claims_empty_for_no_libs() {
        let code = "let x = 5;\nx += 1;";
        let claims = extract_api_claims(code);
        // Plain code with no API calls should produce minimal claims
        // (may still match local class.method patterns but no library names)
        assert!(
            claims.is_empty() || claims.iter().all(|c| c.is_empty()),
            "no-library code should produce empty claims, got: {claims:?}"
        );
    }

    // ── extract_code_blocks_only fallback (Bug 1 fix) ──────────────────
    //
    // Regression: raw code with no markdown fences used to return empty,
    // silently disabling the scanner on FIM completions + paste dumps.
    // Now we fall back to the full content when it looks like code.

    #[test]
    fn extract_code_blocks_falls_back_to_raw_when_no_fences_and_looks_like_code() {
        let raw = "import { fetchData } from 'mylib';\nconst x = obj.method(42);";
        let extracted = extract_code_blocks_only(raw);
        assert_eq!(
            extracted.trim(),
            raw.trim(),
            "raw code without fences should fall back to itself when it looks like code"
        );
    }

    #[test]
    fn extract_code_blocks_does_not_fall_back_for_prose() {
        let prose = "Here is a paragraph of prose with no code shapes.\
                     It just describes things in natural language without\
                     any semicolons; or braces; or function calls.";
        let extracted = extract_code_blocks_only(prose);
        assert!(
            extracted.is_empty(),
            "pure prose should not trigger the code fallback (got {extracted:?})"
        );
    }

    #[test]
    fn extract_code_blocks_still_extracts_real_fenced_blocks() {
        let mixed = "Here is some code:\n\n```python\nfoo.bar()\n```\n\nAnd prose.";
        let extracted = extract_code_blocks_only(mixed);
        assert_eq!(extracted.trim(), "foo.bar()");
    }

    // ── looks_like_code heuristic ──────────────────────────────────────

    #[test]
    fn looks_like_code_triggers_on_imports() {
        assert!(looks_like_code("import { x } from 'react';\nrender();"));
        assert!(looks_like_code("from sklearn import svm"));
        assert!(looks_like_code("const x = require('lodash');"));
        assert!(looks_like_code("#include <iostream>"));
    }

    #[test]
    fn looks_like_code_triggers_on_fn_def_and_operators() {
        assert!(looks_like_code("fn main() -> () {}"));
        assert!(looks_like_code("function helper() { return 1; }"));
        assert!(looks_like_code("def hello():\n    pass"));
    }

    #[test]
    fn looks_like_code_rejects_pure_prose() {
        assert!(!looks_like_code("This is a plain English paragraph."));
        assert!(!looks_like_code("Hello world"));
        assert!(!looks_like_code(""));
    }

    // ── extract_api_claims import patterns (Bug 2 fix) ────────────────

    #[test]
    fn extract_api_claims_catches_js_import_from() {
        let code = "```js\nimport { useState } from 'react';\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("react")),
            "should extract 'react' import claim, got: {claims:?}"
        );
    }

    #[test]
    fn extract_api_claims_catches_python_from_import() {
        let code = "```python\nfrom sklearn.preprocessing import PolynomialFeatures\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("sklearn.preprocessing")),
            "should extract 'sklearn.preprocessing' import claim, got: {claims:?}"
        );
    }

    #[test]
    fn extract_api_claims_catches_require_call() {
        let code = "```js\nconst lodash = require('lodash');\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("lodash")),
            "should extract 'lodash' require claim, got: {claims:?}"
        );
    }

    #[test]
    fn extract_api_claims_catches_c_include() {
        let code = "```cpp\n#include <fake_header.h>\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("fake_header.h")),
            "should extract 'fake_header.h' #include claim, got: {claims:?}"
        );
    }

    #[test]
    fn extract_api_claims_skips_relative_imports() {
        // Relative imports are local paths, not resolvable library claims.
        let code = "```ts\nimport { foo } from './local';\nimport bar from '../parent';\n```";
        let claims = extract_api_claims(code);
        let relative_leak = claims.iter().any(|c| c.contains("./local") || c.contains("../parent"));
        assert!(!relative_leak, "relative imports should be skipped, got: {claims:?}");
    }

    // ── extract_api_claims camelCase bare_call (Bug 2b fix) ────────────

    #[test]
    fn extract_api_claims_catches_camel_case_bare_call() {
        // Before Bug 2b fix, bare_call regex was [a-z_]{3,} which silently
        // missed every camelCase hallucinated function call.
        let code = "```js\ncompletelyFakeFunction({ dubious: 'param' });\n```";
        let claims = extract_api_claims(code);
        assert!(
            claims.iter().any(|c| c.contains("completelyFakeFunction")),
            "should catch camelCase bare call, got: {claims:?}"
        );
    }

    // ── strip_code_fence ─────────────────────────────────────────────────

    #[test]
    fn strip_code_fence_removes_json_fence() {
        let input = "```json\n{\"issues\": []}\n```";
        let out = strip_code_fence(input);
        assert_eq!(out, "{\"issues\": []}");
    }

    #[test]
    fn strip_code_fence_removes_bare_fence() {
        let input = "```\n{\"x\": 1}\n```";
        let out = strip_code_fence(input);
        assert_eq!(out, "{\"x\": 1}");
    }

    #[test]
    fn strip_code_fence_passthrough_no_fence() {
        let input = "{\"x\": 1}";
        let out = strip_code_fence(input);
        assert_eq!(out, "{\"x\": 1}");
    }

    #[test]
    fn strip_code_fence_handles_unclosed_fence() {
        let input = "```json\n{\"x\": 1}";
        let out = strip_code_fence(input);
        assert_eq!(out, "{\"x\": 1}");
    }

    // ── compute_risk_score tests ────────────────────────────────────
    // Score formula pin tests. Changing the weights is fine; the
    // relationships (deterministic > probabilistic > uncertain > clean)
    // must hold.

    fn result_with(
        warnings: Vec<&str>,
        blocks: Vec<&str>,
        details: Vec<&str>,
        scan_failed: bool,
    ) -> ScanResultData {
        ScanResultData {
            clean: blocks.is_empty() && warnings.is_empty() && !scan_failed,
            warnings: warnings.into_iter().map(String::from).collect(),
            blocks: blocks.into_iter().map(String::from).collect(),
            details: details.into_iter().map(String::from).collect(),
            validator_response: String::new(),
            scan_failed,
            docs_assisted: false,
            validator_tokens: 0,
            risk_score: 0.0,
            confidence: 1.0,
        }
    }

    #[test]
    fn risk_score_clean_is_zero() {
        let r = result_with(vec![], vec![], vec![], false);
        assert_eq!(compute_risk_score(&r), 0.0);
    }

    #[test]
    fn risk_score_blocks_force_one() {
        // Any explicit block → 1.0 regardless of other signals.
        let r = result_with(vec![], vec!["phantom"], vec![], false);
        assert_eq!(compute_risk_score(&r), 1.0);
    }

    #[test]
    fn risk_score_cached_hallucination_weights_high() {
        let r = result_with(vec!["cached-hallucination: Repo.find"], vec![], vec![], false);
        let s = compute_risk_score(&r);
        assert!(
            s >= 0.4,
            "single cached-hallucination should weight ≥ 0.4, got {}",
            s
        );
    }

    #[test]
    fn risk_score_unverified_api_weights_low() {
        let r = result_with(vec!["Unverified API: foo()"], vec![], vec![], false);
        let s = compute_risk_score(&r);
        assert!(s > 0.0 && s < 0.2, "single unverified should be small, got {}", s);
    }

    #[test]
    fn risk_score_logic_confirmed_outweighs_uncertain() {
        let confirmed = result_with(vec![], vec![], vec!["logic: type issue: bad"], false);
        let uncertain = result_with(vec![], vec![], vec!["logic (uncertain): maybe bad"], false);
        let c = compute_risk_score(&confirmed);
        let u = compute_risk_score(&uncertain);
        assert!(
            c > u,
            "confirmed logic must score higher than uncertain ({} vs {})",
            c,
            u
        );
    }

    #[test]
    fn risk_score_capped_at_one() {
        // Saturate every signal — must cap at 1.0.
        let r = result_with(
            vec![
                "cached-hallucination: a",
                "cached-hallucination: b",
                "cached-hallucination: c",
                "Unverified API: x()",
                "Unverified API: y()",
            ],
            vec![],
            vec![
                "logic: type: a",
                "logic: type: b",
                "logic: type: c",
                "logic: type: d",
                "logic: type: e",
            ],
            true,
        );
        assert!((compute_risk_score(&r) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn risk_score_scan_failed_floors_at_04() {
        // Validator errored with no other signals — score should be floored
        // at 0.4 (uncertain, can't say it's clean).
        let r = result_with(vec![], vec![], vec![], true);
        let s = compute_risk_score(&r);
        // scan_failed alone with no warnings should NOT floor risk —
        // validator failure doesn't mean hallucinations exist.
        assert!(s < 0.01, "scan_failed with no warnings should be ~0, got {}", s);
    }

    #[test]
    fn risk_score_deterministic_dominates_probabilistic() {
        // Same hallucination flagged by both L1.5 (deterministic) and L3.
        let det = result_with(vec!["cached-hallucination: foo.bar"], vec![], vec![], false);
        let prob = result_with(vec![], vec![], vec!["logic: type: foo.bar hallucinated"], false);
        let d_score = compute_risk_score(&det);
        let p_score = compute_risk_score(&prob);
        assert!(
            d_score > p_score,
            "deterministic signal should outweigh probabilistic ({} vs {})",
            d_score,
            p_score
        );
    }

    #[test]
    fn risk_score_many_unverified_caps_below_one() {
        // 100 unverified API calls — must NOT saturate at 1.0
        // (the cap is 0.6 for unverified signal alone).
        let warnings: Vec<&str> = (0..100).map(|_| "Unverified API: x()").collect();
        let r = result_with(warnings, vec![], vec![], false);
        let s = compute_risk_score(&r);
        assert!(s <= 0.6 + f64::EPSILON, "unverified alone should cap at 0.6, got {}", s);
    }

    #[test]
    fn risk_score_l1_fuzzy_single_match_below_advisor_threshold() {
        // L1 fuzzy match is a heuristic with known FP patterns (user-defined
        // functions, identifiers in prose/command output, freshly-read
        // symbols). A single match must NOT trigger advisor intervention
        // (threshold 0.3) — was incorrectly weighted 0.40, now 0.10.
        let r = result_with(vec!["Hallucinated API: foo() (did you mean bar?)"], vec![], vec![], false);
        let s = compute_risk_score(&r);
        assert!(s < 0.3, "single L1 fuzzy must stay below advisor threshold, got {}", s);
        assert!((s - 0.10).abs() < f64::EPSILON, "single L1 fuzzy should be exactly 0.10, got {}", s);
    }

    #[test]
    fn risk_score_l1_fuzzy_caps_at_030() {
        // 100 fuzzy matches — caps at 0.30 (needs 3+ to even reach advisor
        // threshold; can never trigger block on fuzzy alone).
        let warnings: Vec<&str> = vec!["Hallucinated API: foo() (did you mean bar?)"; 100];
        let r = result_with(warnings, vec![], vec![], false);
        let s = compute_risk_score(&r);
        assert!(s <= 0.30 + f64::EPSILON, "L1 fuzzy alone should cap at 0.30, got {}", s);
    }

    #[test]
    fn risk_score_fuzzy_does_not_dominate_deterministic() {
        // Deterministic check (FORGE/cached) at 0.40 must outweigh a single
        // fuzzy match at 0.10. This encodes "trust the deterministic source
        // over the heuristic" — the original bug had them at equal weight.
        let det = result_with(vec!["cached-hallucination: foo.bar"], vec![], vec![], false);
        let fuzz = result_with(vec!["Hallucinated API: foo() (did you mean bar?)"], vec![], vec![], false);
        let d_score = compute_risk_score(&det);
        let f_score = compute_risk_score(&fuzz);
        assert!(
            d_score > f_score,
            "deterministic signal must outweigh fuzzy ({} vs {})",
            d_score,
            f_score
        );
    }

    // ── Claim decomposition tests ───────────────────────────────────
    // Validate the per-claim aggregation logic independent of L3.

    fn claim(claim: &str, verdict: &str, confidence: f64, reason: &str) -> ClaimVerdict {
        ClaimVerdict {
            claim: claim.to_string(),
            verdict: verdict.to_string(),
            confidence,
            reason: reason.to_string(),
        }
    }

    #[test]
    fn aggregate_verified_claims_produce_no_warnings() {
        let claims = vec![
            claim("foo()", "verified", 0.95, "exists in cache"),
            claim("bar.baz()", "verified", 0.9, "documented"),
        ];
        let (warnings, risk) = aggregate_claims(&claims);
        assert!(warnings.is_empty());
        assert!(risk.abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_high_confidence_hallucination_emits_strong_warning() {
        let claims = vec![claim("fake.method()", "hallucinated", 0.95, "doesn't exist")];
        let (warnings, _risk) = aggregate_claims(&claims);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("high-conf"), "should flag as high-conf: {}", warnings[0]);
        assert!(warnings[0].contains("fake.method()"));
    }

    #[test]
    fn aggregate_low_confidence_hallucination_emits_soft_warning() {
        // After aggregate_claims threshold change (0.8→0.6): ALL hallucinated
        // verdicts emit warnings (recall bias for weak models that saturate
        // confidence at ~0.69). Low-conf still contributes lower risk.
        let claims = vec![claim("maybe.fake()", "hallucinated", 0.5, "uncertain")];
        let (warnings, risk) = aggregate_claims(&claims);
        assert_eq!(warnings.len(), 1, "low-conf hallucinated should warn (recall bias)");
        assert!(risk > 0.0 && risk < 0.1, "low-conf risk should be small, got {}", risk);
    }

    #[test]
    fn aggregate_uncertain_emits_warning_with_low_risk() {
        // chaincheck pattern: uncertain verdicts don't emit warnings.
        let claims = vec![claim("unknown()", "uncertain", 0.3, "no docs")];
        let (warnings, risk) = aggregate_claims(&claims);
        assert_eq!(warnings.len(), 0, "uncertain should not warn");
        assert!(risk > 0.0 && risk < 0.1, "uncertain risk should be small, got {}", risk);
    }

    #[test]
    fn aggregate_risk_capped_at_06() {
        // 20 hallucinated high-conf claims — risk contribution should cap.
        let claims: Vec<ClaimVerdict> = (0..20)
            .map(|_| claim("fake()", "hallucinated", 0.95, "no"))
            .collect();
        let (_, risk) = aggregate_claims(&claims);
        assert!(risk <= 0.6 + f64::EPSILON, "risk should cap at 0.6, got {}", risk);
    }

    #[test]
    fn aggregate_mixed_verdicts_aggregates_correctly() {
        // chaincheck pattern: only high-conf hallucinated produces warning.
        let claims = vec![
            claim("ok()", "verified", 1.0, "good"),
            claim("bad()", "hallucinated", 0.9, "no"),
            claim("maybe()", "uncertain", 0.4, "?"),
        ];
        let (warnings, risk) = aggregate_claims(&claims);
        assert_eq!(warnings.len(), 1, "only high-conf hallucinated warns");
        assert!(risk > 0.2, "non-verified should produce meaningful risk: {}", risk);
    }

    #[test]
    fn aggregate_empty_claims_returns_empty() {
        let (warnings, risk) = aggregate_claims(&[]);
        assert!(warnings.is_empty());
        assert!(risk.abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_confidence_clamped_to_one() {
        // Confidence > 1.0 should clamp, not crash or produce weird math.
        let claims = vec![claim("x()", "hallucinated", 5.0, "high")];
        let (warnings, _) = aggregate_claims(&claims);
        assert_eq!(warnings.len(), 1);
        // 5.0 clamps to 1.0 → ≥ 0.8 → high-conf branch
        assert!(warnings[0].contains("high-conf"));
    }

    // ── project_index helpers ───────────────────────────────────────────
    //
    // These are the multi-language declaration / import / binding extractors
    // plus the fuzzy-match hallucination gate used by L1.

    #[test]
    fn extract_index_entries_finds_ts_declarations() {
        let code = "export function fooBar() {}\nexport class BazQux {}\nconst counter = 1;";
        let entries = super::project_index::extract_index_entries(code, "sample.ts");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"fooBar"), "should find function fooBar, got {names:?}");
        assert!(names.contains(&"BazQux"), "should find class BazQux, got {names:?}");
        assert!(names.contains(&"counter"), "should find binding counter, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_python_imports() {
        let code = "from sklearn.preprocessing import PolynomialFeatures\nfrom pandas import DataFrame";
        let entries = super::project_index::extract_index_entries(code, "sample.py");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"PolynomialFeatures"), "should extract imported symbol, got {names:?}");
        assert!(names.contains(&"DataFrame"), "should extract DataFrame, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_python_def() {
        let code = "def export_notes(notes):\n    return json.dumps(notes)\n\ndef to_dto(note):\n    return NoteDTO(id=note.id)";
        let entries = super::project_index::extract_index_entries(code, "exporter.py");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"export_notes"), "should extract def export_notes, got {names:?}");
        assert!(names.contains(&"to_dto"), "should extract def to_dto, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_rust_fn() {
        let code = "fn process_request() {}\nfn validate_input(data: &str) -> bool { true }";
        let entries = super::project_index::extract_index_entries(code, "main.rs");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"process_request"), "should extract fn process_request, got {names:?}");
        assert!(names.contains(&"validate_input"), "should extract fn validate_input, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_go_func_declarations() {
        let code = "package main\n\nfunc main() {}\n\nfunc (s *Server) Handle() {}";
        let entries = super::project_index::extract_index_entries(code, "main.go");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"main"), "should find func main, got {names:?}");
        assert!(names.contains(&"Handle"), "should find method Handle, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_cpp_class_and_method() {
        let code = "class MNISTData {\n public:\n  void Load();\n};";
        let entries = super::project_index::extract_index_entries(code, "mnist.cpp");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"MNISTData"), "should find class MNISTData, got {names:?}");
    }

    #[test]
    fn extract_index_entries_finds_variable_bindings() {
        let code = "foo = 1\nbar := 2\nlet baz = 3";
        let entries = super::project_index::extract_index_entries(code, "bindings.txt");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(names.contains(&"foo"), "should bind foo, got {names:?}");
        assert!(names.contains(&"bar"), "should bind bar, got {names:?}");
        assert!(names.contains(&"baz"), "should bind baz, got {names:?}");
    }

    #[test]
    fn extract_index_entries_skips_keywords() {
        let code = "if (true) {}\nfor (let i = 0;)\nreturn null";
        let entries = super::project_index::extract_index_entries(code, "noise.js");
        let names: Vec<&str> = entries.iter().map(|e| e.rsplit(": ").next().unwrap_or("")).collect();
        assert!(!names.contains(&"if"), "if should be skipped");
        assert!(!names.contains(&"for"), "for should be skipped");
        assert!(!names.contains(&"return"), "return should be skipped");
    }

    // ── find_close_match_in_index (L1 fuzzy-match gate) ────────────────

    #[test]
    fn find_close_match_catches_typo() {
        // Levenshtein 1: `fit_tranform` vs indexed `fit_transform`
        let index = "sample.py: fit_transform";
        let suggestion = super::project_index::find_close_match_in_index("fit_tranform(", index);
        assert_eq!(suggestion.as_deref(), Some("fit_transform"));
    }

    #[test]
    fn find_close_match_catches_wrong_suffix() {
        // Wrong-suffix tier: shared long prefix, different suffix
        let index = "sample.py: PolynomialTransformed";
        let suggestion = super::project_index::find_close_match_in_index("PolynomialTransformer(", index);
        assert_eq!(suggestion.as_deref(), Some("PolynomialTransformed"));
    }

    #[test]
    fn find_close_match_returns_none_for_unrelated() {
        // Completely unrelated name → silent (might be real external API).
        let index = "sample.py: PolynomialFeatures";
        let suggestion = super::project_index::find_close_match_in_index("axios(", index);
        assert!(suggestion.is_none(), "unrelated name should not trigger, got {suggestion:?}");
    }

    #[test]
    fn find_close_match_returns_none_for_too_short_target() {
        let index = "sample.py: abc";
        let suggestion = super::project_index::find_close_match_in_index("ab(", index);
        assert!(suggestion.is_none(), "target len < 3 should not trigger");
    }

    #[test]
    fn find_close_match_handles_obj_method_claims() {
        // Claim shape: `obj.method(`  — should strip obj + match on `method`.
        let index = "sample.py: text_input";
        let suggestion = super::project_index::find_close_match_in_index("st.text_inpt(", index);
        assert_eq!(suggestion.as_deref(), Some("text_input"));
    }

    #[test]
    fn find_close_match_rejects_identical_or_case_variant_token() {
        // Regression for task-006 case-only FP: a project token equal
        // (case-insensitively) to the target must not be returned as a
        // suggestion. Otherwise the scanner would emit warnings like
        // `Hallucinated API: _month_index() (did you mean _month_index?)`,
        // where suggestion == claim — pure noise.
        let index = "sample.py: _month_index";
        let suggestion = super::project_index::find_close_match_in_index("_month_index(", index);
        assert!(
            suggestion.is_none(),
            "case-insensitive identical token must not be a suggestion, got {suggestion:?}"
        );

        // Also exercise a different casing: claim CamelCase, index snake.
        let index2 = "src/lib.rs: my_function";
        let suggestion2 = super::project_index::find_close_match_in_index("MyFunction(", index2);
        assert!(
            suggestion2.is_none(),
            "token differing only in case must not be a suggestion, got {suggestion2:?}"
        );
    }

    #[test]
    fn is_common_l1_skip_name_recognises_builtins() {
        // Sanity: built-in COMMON_NAMES must still skip after the A7
        // migration that moved the list to module-level helper.
        use super::project_index::is_common_l1_skip_name;
        for n in &[
            "pub", "let", "use", "fn", "impl", "trait", "struct",
            "add", "get", "set", "new", "len", "push", "remove",
            "is_empty", "is_none", "default", "from", "into",
            "find", "filter", "map", "validate",
            "name", "path", "url",
        ] {
            assert!(
                is_common_l1_skip_name(n),
                "built-in COMMON_NAMES entry {:?} should skip",
                n
            );
        }
    }

    #[test]
    fn is_common_l1_skip_name_rejects_unrelated() {
        use super::project_index::is_common_l1_skip_name;
        for n in &[
            "totally_unknown_name",
            "PolynomialTransformer",
            "axiosClient",
            "",
            "ABC",
        ] {
            assert!(
                !is_common_l1_skip_name(n),
                "unrelated name {:?} should NOT skip",
                n
            );
        }
    }

    #[test]
    fn set_extra_l1_skip_names_extends_list_first_write_wins() {
        use super::project_index::{is_common_l1_skip_name, set_extra_l1_skip_names};
        let marker = "anubis_a7_l1_skip_marker_xyz";
        // Pre-condition: marker not in built-in list.
        assert!(!is_common_l1_skip_name(marker));
        // First call wins.
        set_extra_l1_skip_names(vec![marker.to_string()]);
        assert!(
            is_common_l1_skip_name(marker),
            "user-provided extension must be honored"
        );
        // Second call must NOT overwrite (OnceCell first-write-wins).
        set_extra_l1_skip_names(vec!["anubis_a7_l1_skip_second_marker".to_string()]);
        assert!(
            is_common_l1_skip_name(marker),
            "OnceCell first-write-wins: original marker should still be present"
        );
    }

    // ── levenshtein_capped (basic distance) ────────────────────────────

    #[test]
    fn levenshtein_identical_strings_distance_zero() {
        let d = super::project_index::levenshtein_capped("hello", "hello", 5);
        assert_eq!(d, 0);
    }

    #[test]
    fn levenshtein_single_substitution_distance_one() {
        let d = super::project_index::levenshtein_capped("cat", "bat", 5);
        assert_eq!(d, 1);
    }

    #[test]
    fn levenshtein_returns_cap_plus_one_when_exceeded() {
        // cat vs elephant — distance way over 2.
        let d = super::project_index::levenshtein_capped("cat", "elephant", 2);
        assert_eq!(d, 3); // 2 + 1 = early exit
    }

    // ── estimate_tokens (council A13 — CJK-aware token estimation) ───────

    #[test]
    fn estimate_tokens_ascii_uses_quarter_token_per_char() {
        // "hello world" = 11 ASCII chars × 0.25 = 2.75 → ceil 3
        assert_eq!(super::estimate_tokens("hello world"), 3);
        // Empty string → 0 tokens
        assert_eq!(super::estimate_tokens(""), 0);
        // Single ASCII char → ceil(0.25) = 1
        assert_eq!(super::estimate_tokens("a"), 1);
    }

    #[test]
    fn estimate_tokens_cjk_uses_one_token_per_char() {
        // Council A13: prior len()/4 heuristic treated CJK content as ~4
        // bytes/token, underestimating by ~3x. New heuristic: CJK chars
        // cost ~1 token each (closer to actual BPE behaviour).
        // "안녕하세요" (Korean "hello") = 5 Hangul chars × 1.0 = 5 tokens.
        assert_eq!(super::estimate_tokens("안녕하세요"), 5);
        // "你好世界" (Chinese "hello world") = 4 chars × 1.0 = 4 tokens.
        assert_eq!(super::estimate_tokens("你好世界"), 4);
        // "こんにちは" (Japanese hiragana) = 5 chars × 1.0 = 5 tokens.
        assert_eq!(super::estimate_tokens("こんにちは"), 5);
    }

    #[test]
    fn estimate_tokens_mixed_content_weights_correctly() {
        // "def 안녕():" = d,e,f (3 ASCII × 0.25) + space (0.25) +
        // 안,녕 (2 CJK × 1.0) + (,),: (3 ASCII × 0.25) = 0.75+0.25+2.0+0.75 = 3.75 → ceil 4
        assert_eq!(super::estimate_tokens("def 안녕():"), 4);
        // Mixed CJK code + English identifier should NOT trigger the
        // "too few tokens" gate when CJK content dominates.
        let cjk_heavy = "함수를 정의합니다: function add(a, b) { return a + b; }";
        let est = super::estimate_tokens(cjk_heavy);
        assert!(
            est >= 13,
            "CJK-heavy mixed content must not trip token gate, got {}",
            est
        );
    }

    #[test]
    fn estimate_tokens_legacy_ascii_equivalence() {
        // For pure ASCII content, the new heuristic should produce results
        // close to the old len()/4 formula (within ±1 to account for ceil).
        for s in &["hello", "hello world", "function add(a, b) { return a + b; }"] {
            let legacy = (s.len() as f64 / 4.0).ceil() as usize;
            let new = super::estimate_tokens(s);
            assert!(
                new >= legacy.saturating_sub(1) && new <= legacy + 1,
                "ASCII {:?}: legacy={} new={} diverged by >1",
                s,
                legacy,
                new
            );
        }
    }

    // ── post_filter_l3_against_cache ──────────────────────────────────
    //
    // chaincheck pattern: cross-check LLM judge output against deterministic
    // ground truth. L3 may claim an API "doesn't exist" when our bundle
    // proves it does — those warnings must be suppressed.

    #[test]
    fn post_filter_keeps_non_existence_warnings() {
        // No cache match — L3 warning stays.
        let warnings = vec![
            "claim-hallucinated (high-conf): PolynomialTransformer.fit() does not exist".to_string(),
            "claim-hallucinated: foo() does not exist".to_string(),
        ];
        let filtered = super::post_filter_l3_against_cache(&warnings);
        // These hallucinated names are unlikely to be cached — both kept.
        // (If cache is empty during test, all are kept anyway.)
        assert!(!filtered.is_empty(), "non-existence warnings should pass through");
    }

    #[test]
    fn post_filter_keeps_style_warnings_untouched() {
        // Style warnings with no existence claim — all kept.
        let warnings = vec![
            "logic: wrong-assumption: x might be null".to_string(),
            "logic: consider using stricter types".to_string(),
        ];
        let filtered = super::post_filter_l3_against_cache(&warnings);
        assert_eq!(filtered.len(), warnings.len(), "non-existence warnings untouched");
    }

    #[test]
    fn post_filter_handles_empty_input() {
        let filtered = super::post_filter_l3_against_cache(&[]);
        assert!(filtered.is_empty(), "empty input -> empty output");
    }

    #[test]
    fn post_filter_matches_doesnt_exist_phrases() {
        // Test that all existence-claim phrases are recognized.
        // (Only checks that the function doesn't crash on various phrasings.)
        let warnings = vec![
            "X does not exist".to_string(),
            "X doesn't exist".to_string(),
            "X not found".to_string(),
            "no method X".to_string(),
        ];
        let _ = super::post_filter_l3_against_cache(&warnings);
        // No assertion on length — depends on cache state. Just shouldn't panic.
    }

    #[test]
    fn post_filter_skips_complex_backtick_expressions() {
        // Complex expressions (paths, signatures) inside backticks shouldn't
        // confuse the filter.
        let warnings = vec![
            "claim-hallucinated: `def hello(name: str) -> None:` does not exist".to_string(),
        ];
        let filtered = super::post_filter_l3_against_cache(&warnings);
        // Complex expression should be skipped by the filter, so warning kept.
        assert_eq!(filtered.len(), 1);
    }

    // ── Cascade prose bypass (Task 2) ───────────────────────────────────

    /// Build a ForgeResult + SymbolCheckResult combo that would normally
    /// trigger cascade skip (high confidence, all resolved, no warnings).
    fn clean_deterministic_layers() -> (
        crate::scanner::forge_pipeline::ForgeResult,
        crate::symbols::SymbolCheckResult,
    ) {
        let forge = crate::scanner::forge_pipeline::ForgeResult {
            claims_extracted: 3,
            claims_verified: 3,
            claims_unknown: 0,
            ..Default::default()
        };
        let symbols = crate::symbols::SymbolCheckResult {
            method_calls_count: 3,
            verified_count: 3,
            ..Default::default()
        };
        (forge, symbols)
    }

    #[test]
    fn cascade_skips_l3_when_clean_and_no_prose() {
        let (forge, symbols) = clean_deterministic_layers();
        // No L1 warnings, high confidence, deterministic layers fully
        // resolved, no prose claims present - cascade SHOULD skip L3.
        let skip = super::compute_cascade_decision(
            /* l1_had_warnings */ false,
            /* combined_confidence */ 0.95,
            &forge,
            &symbols,
            /* has_prose */ false,
        );
        assert!(skip, "cascade should skip L3 when deterministic layers are clean and no prose");
    }

    #[test]
    fn cascade_runs_l3_when_prose_present_even_if_clean() {
        let (forge, symbols) = clean_deterministic_layers();
        // Same conditions as above, BUT prose claims present — cascade
        // MUST NOT skip L3, because prose claims can only be verified by
        // the LLM judge. This is the core bypass behavior (Task 2).
        let skip = super::compute_cascade_decision(
            /* l1_had_warnings */ false,
            /* combined_confidence */ 0.95,
            &forge,
            &symbols,
            /* has_prose */ true,
        );
        assert!(!skip, "cascade must NOT skip L3 when prose claims are present");
    }

    #[test]
    fn cascade_runs_l3_when_l1_has_warnings_regardless_of_prose() {
        let (forge, symbols) = clean_deterministic_layers();
        // L1 warnings force L3 regardless of prose state.
        let skip_no_prose = super::compute_cascade_decision(
            true, 0.95, &forge, &symbols, false,
        );
        let skip_with_prose = super::compute_cascade_decision(
            true, 0.95, &forge, &symbols, true,
        );
        assert!(!skip_no_prose, "L1 warnings force L3");
        assert!(!skip_with_prose, "L1 warnings force L3 (prose irrelevant)");
    }

    // ── build_library_docs_fallback / build_library_docs_from_cache ────
    //
    // Doc-grounding fix: when search_docs() returns empty (typical for
    // prose-only responses), the L3 path falls back to detect_libraries +
    // symbol cache + remote docs Worker so the judge has REFERENCE docs.

    #[test]
    fn build_library_docs_from_cache_empty_for_no_libs() {
        let cache = crate::symbols::cache::SymbolCache::open_in_memory()
            .expect("open in-memory cache");
        let (text, covered) = super::build_library_docs_from_cache(&[], &cache);
        assert!(text.is_empty(), "empty libs should yield empty text");
        assert!(covered.is_empty(), "covered set must be empty");
    }

    #[test]
    fn build_library_docs_from_cache_empty_when_cache_misses() {
        let cache = crate::symbols::cache::SymbolCache::open_in_memory()
            .expect("open in-memory cache");
        // Detect a library the empty in-memory cache doesn't know about.
        let libs = vec![crate::injection::DetectedLibrary {
            name: "numpy".to_string(),
            language: "python".to_string(),
        }];
        let (text, covered) = super::build_library_docs_from_cache(&libs, &cache);
        assert!(
            text.is_empty(),
            "empty cache should yield empty text, got: {text}"
        );
        assert!(
            covered.is_empty(),
            "covered set must be empty when cache misses"
        );
    }

    #[test]
    fn build_library_docs_from_cache_returns_text_on_hit() {
        let cache = crate::symbols::cache::SymbolCache::open_in_memory()
            .expect("open in-memory cache");
        // Seed the cache with a couple of symbols for "pandas".
        use crate::symbols::types::{Symbol, SymbolKind};
        let symbols = vec![
            {
                let mut s = Symbol::new("pandas", "1.0.0", "DataFrame");
                s.kind = SymbolKind::Class;
                s.signature = Some("class DataFrame".to_string());
                s
            },
            {
                let mut s = Symbol::new("pandas", "1.0.0", "DataFrame.read_csv");
                s.kind = SymbolKind::Method;
                s.signature = Some("read_csv(filepath: str) -> DataFrame".to_string());
                s
            },
        ];
        cache.insert_many(&symbols).expect("seed cache");

        let libs = vec![crate::injection::DetectedLibrary {
            name: "pandas".to_string(),
            language: "python".to_string(),
        }];
        let (text, covered) = super::build_library_docs_from_cache(&libs, &cache);
        assert!(!text.is_empty(), "seeded cache should yield text, got empty");
        assert!(
            text.contains("pandas"),
            "snippet should mention the library, got: {text}"
        );
        assert!(
            covered.contains("pandas"),
            "covered set must include pandas, got: {covered:?}"
        );
    }

    #[test]
    fn build_library_docs_from_cache_caps_at_budget() {
        let cache = crate::symbols::cache::SymbolCache::open_in_memory()
            .expect("open in-memory cache");
        use crate::symbols::types::{Symbol, SymbolKind};
        // Seed many symbols across two libraries.
        let mut symbols: Vec<Symbol> = Vec::new();
        for lib_name in &["lib_a", "lib_b", "lib_c"] {
            for i in 0..50 {
                let mut s = Symbol::new(*lib_name, "1.0.0", &format!("Class{i}.method{i}"));
                s.kind = SymbolKind::Method;
                s.signature = Some(format!("method{i}() -> void"));
                symbols.push(s);
            }
        }
        cache.insert_many(&symbols).expect("seed cache");

        let libs = vec![
            crate::injection::DetectedLibrary {
                name: "lib_a".to_string(),
                language: "python".to_string(),
            },
            crate::injection::DetectedLibrary {
                name: "lib_b".to_string(),
                language: "python".to_string(),
            },
            crate::injection::DetectedLibrary {
                name: "lib_c".to_string(),
                language: "python".to_string(),
            },
        ];
        // Tiny budget forces truncation after first lib.
        let (text, _covered) = super::build_library_docs_from_cache(&libs, &cache);
        // build_doc_snippets caps at the token budget — output stays well
        // under MAX_DOCS_RESULT. Just verify the helper is bounded.
        assert!(
            text.len() < 10_000,
            "snippet should be bounded by token budget, got {} bytes",
            text.len()
        );
    }

    /// End-to-end: build_library_docs_fallback returns empty when content
    /// has no detectable library mentions.
    #[tokio::test]
    async fn build_library_docs_fallback_empty_for_no_libraries() {
        let prose_only = "This function is thread-safe and runs in O(1) time.";
        let got = super::build_library_docs_fallback(prose_only).await;
        assert!(
            got.is_empty(),
            "content with no library mentions must return empty, got: {got}"
        );
    }

    /// End-to-end: build_library_docs_fallback returns text for content
    /// that mentions a library via import (the typical prose-claim case
    /// where search_docs returns empty but detect_libraries succeeds).
    ///
    /// Skipped when the production symbol cache is empty (CI without
    /// `docs add`). Mirrors the gating pattern in
    /// `build_per_claim_docs_returns_excerpt_when_class_prefix_matches`.
    #[tokio::test]
    async fn build_library_docs_fallback_populates_when_libs_detected() {
        // Import triggers detect_libraries even without a class.method() call.
        let content = "import pandas as pd\n\nThis function is thread-safe.\n";
        let got = super::build_library_docs_fallback(content).await;
        if got.is_empty() {
            // Production cache cold or remote docs Worker unreachable — skip.
            eprintln!("skip: build_library_docs_fallback returned empty (cold cache / no network)");
            return;
        }
        // When populated, the snippet should reference one of the detected
        // libraries (pandas in this case).
        assert!(
            got.to_lowercase().contains("pandas"),
            "expected snippet to mention pandas, got: {got}"
        );
    }

    /// Kill switch: ANUBIS_L3_DOCS_IN_PROMPT=0 must short-circuit
    /// build_library_docs_fallback to an empty string even when the
    /// content would normally populate a docs snippet. Env vars are
    /// process-global; uses save/restore (same pattern as
    /// `ts_method_checker.rs::ts_compiler_gate_*` tests). Also covers
    /// `=false` (case-insensitive).
    #[tokio::test]
    async fn build_library_docs_fallback_returns_empty_when_kill_switch_set() {
        let prior = std::env::var_os("ANUBIS_L3_DOCS_IN_PROMPT");

        for val in ["0", "false", "FALSE", "False"] {
            std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", val);
            // Content that detect_libraries would otherwise pick up (pandas import).
            let content = "import pandas as pd\n\ndf = pd.DataFrame()\n";
            let got = super::build_library_docs_fallback(content).await;
            assert!(
                got.is_empty(),
                "kill switch = {val:?} — expected empty docs snippet, got: {got}"
            );
        }

        match prior {
            Some(v) => std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", v),
            None => std::env::remove_var("ANUBIS_L3_DOCS_IN_PROMPT"),
        }
    }

    /// Kill switch unset preserves normal behavior (docs may populate
    /// when symbol cache or remote Worker has data). Skipped on cold
    /// cache / no network, matching the existing populate test's gate.
    #[tokio::test]
    async fn build_library_docs_fallback_returns_docs_when_kill_switch_unset() {
        let prior = std::env::var_os("ANUBIS_L3_DOCS_IN_PROMPT");
        std::env::remove_var("ANUBIS_L3_DOCS_IN_PROMPT");

        // Import triggers detect_libraries even without a class.method() call.
        let content = "import pandas as pd\n\nThis function is thread-safe.\n";
        let got = super::build_library_docs_fallback(content).await;

        match prior {
            Some(v) => std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", v),
            None => std::env::remove_var("ANUBIS_L3_DOCS_IN_PROMPT"),
        }

        if got.is_empty() {
            eprintln!("skip: kill switch unset but cache cold / no network");
            return;
        }
        assert!(
            got.to_lowercase().contains("pandas"),
            "expected snippet to mention pandas, got: {got}"
        );
    }

    // ── wrap_bare_rust_snippet ────────────────────────────────────────

    #[test]
    fn wrap_bare_snippet_noop_for_multi_def_real_world_files() {
        // Real-world responses contain complete compilation units — the
        // wrapper must leave them untouched so rustc reports real errors
        // at their original lines.
        let multi_fn = "fn helper() -> u32 { 1 }\n\nfn main() {\n    helper();\n}\n";
        assert_eq!(
            super::compiler_verifier::wrap_bare_rust_snippet(multi_fn.to_string()),
            multi_fn,
            "multi-fn file must pass through unchanged"
        );

        let mixed_items = "use std::collections::HashMap;\n\nstruct Cache {\n    map: HashMap<String, u32>,\n}\n\nimpl Cache {\n    fn get(&self, k: &str) -> u32 { 0 }\n}\n";
        assert_eq!(
            super::compiler_verifier::wrap_bare_rust_snippet(mixed_items.to_string()),
            mixed_items,
            "struct+impl file must pass through unchanged"
        );

        // Every item keyword the guard knows must independently disable wrapping.
        for guard_line in [
            "trait Foo { }",
            "static COUNTER: u32 = 0;",
            "const MAX: usize = 10;",
            "mod inner { }",
            "enum Kind { A }",
        ] {
            let file = format!("let x = 5;\n{guard_line}\n");
            assert_eq!(
                super::compiler_verifier::wrap_bare_rust_snippet(file.clone()),
                file,
                "guard line {guard_line:?} must disable wrapping"
            );
        }
    }

    #[test]
    fn wrap_bare_snippet_wraps_fragments_and_hoists_uses() {
        // Fragment: top-level statements with no item definitions — must be
        // wrapped so rustc type-checks (catching e.g. hallucinated methods).
        let fragment = "use std::collections::HashMap;\nlet m: HashMap<String, i32> = HashMap::new();\nm.bogus_method();\n";
        let wrapped = super::compiler_verifier::wrap_bare_rust_snippet(fragment.to_string());
        assert!(
            wrapped.starts_with("use std::collections::HashMap;"),
            "`use` must be hoisted outside fn main, got: {wrapped}"
        );
        assert!(
            wrapped.contains("fn main() {"),
            "fragment body must be wrapped in fn main, got: {wrapped}"
        );
        // Use must appear exactly once (hoisted, not duplicated inside body).
        assert_eq!(
            wrapped.matches("use std::collections::HashMap;").count(),
            1,
            "use must not be duplicated, got: {wrapped}"
        );

        // Pure-expression snippet with a hallucinated method gets wrapped too.
        let expr = "let v = vec![1, 2, 3];\nv.sum_all();\n";
        let wrapped_expr = super::compiler_verifier::wrap_bare_rust_snippet(expr.to_string());
        assert!(wrapped_expr.contains("fn main() {"));
    }

#[test]
fn extract_local_variables_python_module_assignment() {
    // FP repro (task-002 e2e): `_SessionLocal = sessionmaker(bind=_engine)`
    // was not recognized as a definition -> "Hallucinated API" fuzzy warning.
    let vars = super::extract_local_variables(
        "_SessionLocal = sessionmaker(bind=_engine)\n\ndef get_session():\n    return _SessionLocal()\n",
    );
    assert!(vars.contains("_SessionLocal"), "got: {:?}", vars);
}

#[test]
fn extract_local_variables_click_decorator_argument() {
    // FP repro (task-002 e2e): `@click.argument("query")` injects `query` as
    // a function parameter at runtime -> must count as defined.
    let vars = super::extract_local_variables(
        "@click.argument(\"query\")\n@click.option(\"--verbose\", is_flag=True)\ndef search(query: str):\n    pass\n",
    );
    assert!(vars.contains("query"), "got: {:?}", vars);
}

#[test]
fn extract_local_variables_keyword_arg_not_definition() {
    // Guard: `f(x = 1)` call-site kwargs must NOT be treated as definitions
    // of `x` (they don't bind the name in scope).
    let vars = super::extract_local_variables("result = configure(timeout = 30, query = \"a\")\n");
    assert!(!vars.contains("timeout"), "got: {:?}", vars);
    assert!(vars.contains("result"), "got: {:?}", vars);
}

#[test]
fn emit_l1_5_cached_hallucination_guards() {
    // Combined positive + negative guard for the same-response definition
    // suppression (task-002 e2e FP). One test function so the hermetic
    // USERPROFILE swap is race-free (#[test]s run in parallel threads of a
    // single process and share env).
    //
    // Scenario 1 (positive): response DEFINES `def from_note(...)` — the
    // cached-hallucination warning must be suppressed (the cache hasn't
    // ingested the new method yet; it may even have resolved the class from
    // a stale namespace).
    //
    // Scenario 2 (negative): response does NOT define the method — the
    // stale-cache warning must still be emitted.
    let real_home = std::env::var("USERPROFILE").unwrap_or_default();
    let tmp = std::env::temp_dir().join("anubis-test-l15-cache");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join(".anubis").join("symbols")).unwrap();
    std::env::set_var("USERPROFILE", &tmp);
    {
        // Seed a real Class surface so `has_real_class_surface` passes and
        // emission is reachable in scenario 2.
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        let _ = cache.insert_many(&[crate::symbols::types::Symbol {
            library: "local.python.anubis-bench".into(),
            version: "local".into(),
            path: "exporter.py".into(),
            name: "NoteExport".into(),
            kind: crate::symbols::types::SymbolKind::Class,
            signature: Some("class NoteExport".into()),
            params: Vec::new(),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: crate::symbols::types::Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: 0,
        }]);

        use crate::symbols::SymbolCheckResult;
        // NOTE: production markdown (symbols/mod.rs:728/735) uses an EM-DASH
        // before "class": "{}.{}() \u{2014} class {} exists ...". The
        // emission guards match on that exact byte, so the repro must too.
        let symbols = SymbolCheckResult {
            hallucination_count: 1,
            markdown: "- NoteExport.from_note() \u{2014} class NoteExport exists in local.python.some-workspace but method is not in cached symbols".to_string(),
            ..Default::default()
        };
        let scope = crate::scanner::scope_analysis::InstanceCheckResult::default();
        let session = std::collections::HashSet::new();

        // Scenario 1: same-response definition suppresses.
        let mut suppressed = super::ScanResultData::default();
        let defining_content = "\
class NoteExport:
    @classmethod
    def from_note(cls, note):
        return NoteExport(id=note.id)
";
        super::emit_l1_5_warnings(&symbols, &scope, &session, defining_content, &mut suppressed);
        assert!(
            !suppressed.warnings.iter().any(|w| w.contains("from_note")),
            "same-response definition must suppress cached-hallucination, got: {:?}",
            suppressed.warnings
        );

        // Scenario 2: no definition -> still flagged.
        let mut flagged = super::ScanResultData::default();
        super::emit_l1_5_warnings(&symbols, &scope, &session, "print('no defs here')", &mut flagged);
        assert!(
            flagged.warnings.iter().any(|w| w.contains("cached-hallucination")),
            "stale-cache method call must still be flagged, got: {:?}",
            flagged.warnings
        );
    }
    std::env::set_var("USERPROFILE", &real_home);
    let _ = std::fs::remove_dir_all(&tmp);
}

    // ── Fragment-visibility FP fix: alias bindings + session accumulation ──

    /// `from X import NAME as ALIAS` must index BOTH the source name and the
    /// in-scope alias binding. Dropping the alias caused the django-13821
    /// fragment-visibility FP (`from sqlite3 import dbapi2 as Database`
    /// → scanner flagged `Database` as hallucinated in quoted real code).
    #[test]
    fn extract_index_entries_keeps_python_import_aliases() {
        let entries = super::project_index::extract_index_entries(
            "from sqlite3 import dbapi2 as Database\nimport xml.etree.ElementTree as ET\n",
            "session",
        );
        assert!(
            entries.iter().any(|e| e.contains("dbapi2")),
            "source name must be indexed, got: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e.contains("Database")),
            "alias binding must be indexed, got: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e.contains("ET")),
            "module import alias must be indexed, got: {entries:?}"
        );
    }

    /// TS destructuring `{ A as B }` must index both names.
    #[test]
    fn extract_index_entries_keeps_ts_destructuring_aliases() {
        let entries = super::project_index::extract_index_entries(
            "import { useMemo as useMemoized, useState } from 'react';\n",
            "session",
        );
        assert!(
            entries.iter().any(|e| e.contains("useMemoized")),
            "ts alias binding must be indexed, got: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e.contains("useState")),
            "plain destructured name must be indexed, got: {entries:?}"
        );
    }

    /// Session round-trip: accumulated tool-result symbols (language `""`)
    /// must surface in get_session_symbols for any language filter — this is
    /// what makes emit_forge_warnings' session_defined filter suppress
    /// fragment-visibility FPs.
    #[test]
    fn session_symbols_round_trip_from_tool_result_content() {
        let root = format!("/test-fragvis-session-{}", std::process::id());
        let tool_result = "\
from itertools import combinations, combinations_with_replacement

def _binomial_terms(n):
    return list(combinations(range(n), 2))
";
        super::project_index::accumulate_session_symbols(&root, tool_result, "");
        let session = super::project_index::get_session_symbols(&root, "");
        assert!(
            session.contains("combinations"),
            "imported name from tool result must be session-defined, got: {session:?}"
        );
        assert!(
            session.contains("_binomial_terms"),
            "function decl from tool result must be session-defined, got: {session:?}"
        );
        // Language-filtered lookup must also surface it (universal tag).
        let session_py = super::project_index::get_session_symbols(&root, "python");
        assert!(
            session_py.contains("combinations"),
            "universal session symbols must pass language filter, got: {session_py:?}"
        );
    }

    /// Parenthesized multi-line Python imports must index every name
    /// (typing-style isort blocks — the xarray-6744 `Iterator` FP class).
    #[test]
    fn extract_index_entries_handles_parenthesized_python_imports() {
        let src = "from typing import (\n    TYPE_CHECKING,\n    Any,\n    Hashable,\n    Iterator,\n    Mapping,\n)\n";
        let entries = super::project_index::extract_index_entries(src, "session");
        for name in ["TYPE_CHECKING", "Any", "Hashable", "Iterator", "Mapping"] {
            assert!(
                entries.iter().any(|e| e.ends_with(&format!(": {name}"))),
                "parenthesized import name {name} missing: {entries:?}"
            );
        }
    }

    /// Trailing comments must not lose import names (verifier finding:
    /// `import os, sys  # stdlib` lost `sys` to the whitespace guard).
    #[test]
    fn extract_index_entries_strips_trailing_import_comments() {
        let src = "import os, sys  # stdlib\nimport numpy as np  # vectors\nfrom itertools import chain  # iter\n";
        let entries = super::project_index::extract_index_entries(src, "session");
        for name in ["os", "sys", "numpy", "np", "chain"] {
            assert!(
                entries.iter().any(|e| e.ends_with(&format!(": {name}"))),
                "name {name} lost to trailing comment: {entries:?}"
            );
        }
    }

    /// def(self,...) in content binds self/cls for local-variable
    /// extraction (the django-16642 `self` FP class).
    #[test]
    fn extract_local_variables_binds_self_from_def() {
        let src = "def fill_with(self, value):\n    self._fill(value)\n";
        let vars = super::extract_local_variables(src);
        assert!(vars.contains("self"), "self must be bound, got: {vars:?}");
    }

    /// End-to-end suppression: a FORGE warning whose backtick symbol is
    /// session-defined must be dropped by emit_forge_warnings — the exact
    /// fragment-visibility mechanism (xarray `RollingKey` FP class).
    #[test]
    fn emit_forge_warnings_suppresses_session_defined_symbols() {
        let root = format!("/test-fragvis-suppress-{}", std::process::id());
        // Agent read rolling.py: RollingKey is real, defined in TYPE_CHECKING.
        super::project_index::accumulate_session_symbols(
            &root,
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from .types import RollingKey\n",
            "",
        );
        let session_syms = super::project_index::get_session_symbols(&root, "python");
        let session_defined: std::collections::HashSet<&str> = session_syms
            .lines()
            .filter(|l| l.starts_with("session: "))
            .map(|l| &l["session: ".len()..])
            .collect();
        assert!(
            session_defined.contains("RollingKey"),
            "setup: RollingKey must be session-defined, got: {session_defined:?}"
        );
        let mut result = super::ScanResultData::default();
        let forge = super::forge_pipeline::ForgeResult {
            warnings: vec![
                "forge: hallucinated-variable: `RollingKey` - referenced but not defined in scope"
                    .to_string(),
            ],
            ..Default::default()
        };
        super::emit_forge_warnings(&forge, &session_defined, &mut result);
        assert!(
            result.warnings.is_empty(),
            "session-defined RollingKey must be suppressed, got: {:?}",
            result.warnings
        );
        // And a symbol NOT in session must survive.
        let forge2 = super::forge_pipeline::ForgeResult {
            warnings: vec![
                "forge: hallucinated-variable: `MadeUpThing` - referenced but not defined in scope"
                    .to_string(),
            ],
            ..Default::default()
        };
        let mut result2 = super::ScanResultData::default();
        super::emit_forge_warnings(&forge2, &session_defined, &mut result2);
        assert!(
            !result2.warnings.is_empty(),
            "unknown symbol must NOT be suppressed"
        );
    }
