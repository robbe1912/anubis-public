use anubis_daemon::scanner::l3_per_claim::{extract_prose_claims, extract_identifier_anchored_claims};

#[test]
fn diagnose_py_sorted() {
    let content = "```python\nxs = [3, 1, 2]\nresult = sorted(xs)\nprint(xs)\n```\n\nSorts xs in place so the original list becomes [1, 2, 3] after the call.";
    let prose = extract_prose_claims(content);
    let idc = extract_identifier_anchored_claims(content);
    eprintln!("PROSE: {prose:?}");
    eprintln!("ID: {idc:?}");
    assert!(prose.len() + idc.len() > 0, "no claims extracted — L3 cannot fire");
}

#[test]
fn diagnose_go_splitn() {
    let content = "```go\npackage main\n\nimport \"strings\"\n\nfunc main() {\n\tparts := strings.SplitN(\"a,b,c\", \",\")\n\t_ = parts\n}\n```\n\nSplits the string into parts using strings.SplitN with a single separator argument.";
    let prose = extract_prose_claims(content);
    let idc = extract_identifier_anchored_claims(content);
    eprintln!("PROSE: {prose:?}");
    eprintln!("ID: {idc:?}");
    assert!(prose.len() + idc.len() > 0, "no claims extracted");
}

#[test]
fn diagnose_gd_tween() {
    let content = "```gdscript\nextends Node\n\nfunc _ready():\n    var tween = Tween.new()\n    add_child(tween)\n```\n\nInstantiates a Tween directly with Tween.new and adds it to the tree.";
    let prose = extract_prose_claims(content);
    let idc = extract_identifier_anchored_claims(content);
    eprintln!("PROSE: {prose:?}");
    eprintln!("ID: {idc:?}");
    assert!(prose.len() + idc.len() > 0, "no claims extracted");
}
