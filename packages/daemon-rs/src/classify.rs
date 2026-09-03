// Request classifier — detects compaction/background traffic.
// Mirrors packages/proxy/src/classify.ts.

use serde::{Deserialize, Serialize};

/// Request classification result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RequestClass {
    Chat,
    Compaction,
    Background,
    #[default]
    Unknown,
}

/// Human-readable classification result.
#[derive(Debug, Clone, Serialize)]
pub struct ClassificationResult {
    #[serde(flatten)]
    pub class: RequestClassWrapper,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestClassWrapper {
    #[serde(rename = "type")]
    pub class: String,
}

/// Markers that indicate compaction (specific, unambiguous phrases).
const COMPACTION_MARKERS: &[&str] = &[
    "summarize the conversation",
    "compact the conversation",
    "anchored summary",
    "context was compacted",
    "continue if you have next steps",
    "summarize this conversation",
    "summarize the following",
    "compress the context",
    "create a summary of",
    "here is a summary of the conversation",
    "previous conversation summary",
    "summarize chat history",
];

/// Co-occurring marker groups — ALL must appear for a match.
const COMPACTION_GROUPS: &[&[&str]] = &[
    &["## goal", "## progress", "## key decisions"],
    &["## critical context", "## relevant files"],
];

/// Background task markers.
const BACKGROUND_MARKERS: &[&str] = &[
    "generate a concise title",
    "suggest a title",
    "categorize this",
    "classify this message",
    "extract keywords",
];

/// Classify a request by inspecting its parsed body.
pub fn classify_request(body: &serde_json::Value) -> ClassificationResult {
    let messages = body.get("messages").and_then(|m| m.as_array());
    let tools = body.get("tools").and_then(|t| t.as_array());
    let stream = body
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    let messages = messages.cloned().unwrap_or_default();
    let tool_count = tools.map(|t| t.len()).unwrap_or(0);

    // Extract text from last user message
    let last_user_text = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .map(|m| extract_text(m.get("content")))
        .unwrap_or_default();

    // Extract system prompt
    let system_text = messages
        .iter()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .map(|m| extract_text(m.get("content")))
        .unwrap_or_default();

    let combined = format!("{}\n{}", system_text, last_user_text).to_lowercase();

    // Check 1: Compaction markers (specific phrases)
    for marker in COMPACTION_MARKERS {
        if combined.contains(marker) {
            return ClassificationResult {
                class: RequestClassWrapper {
                    class: "compaction".to_string(),
                },
                reason: format!("content matches \"{}\"", marker),
            };
        }
    }

    // Check 1b: Co-occurring compaction marker groups
    for group in COMPACTION_GROUPS {
        if group.iter().all(|m| combined.contains(m)) {
            return ClassificationResult {
                class: RequestClassWrapper {
                    class: "compaction".to_string(),
                },
                reason: format!("co-occurring markers: {}", group.join(" + ")),
            };
        }
    }

    // Check 2: Background task markers
    for marker in BACKGROUND_MARKERS {
        if combined.contains(marker) {
            return ClassificationResult {
                class: RequestClassWrapper {
                    class: "background".to_string(),
                },
                reason: format!("content matches \"{}\"", marker),
            };
        }
    }

    // Check 3: Structural signals — likely background
    if tool_count == 0 && messages.len() <= 3 && !stream {
        let sys_lower = system_text.to_lowercase();
        if sys_lower.contains("summari") || sys_lower.contains("compact") {
            return ClassificationResult {
                class: RequestClassWrapper {
                    class: "background".to_string(),
                },
                reason: "non-streaming + no tools + short + summary system prompt".to_string(),
            };
        }
    }

    ClassificationResult {
        class: RequestClassWrapper {
            class: "chat".to_string(),
        },
        reason: "standard chat request".to_string(),
    }
}

/// Extract text from message content (string or array of parts).
fn extract_text(content: Option<&serde_json::Value>) -> String {
    match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|part| {
                if let Some(s) = part.as_str() {
                    Some(s.to_string())
                } else if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                    Some(t.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}
