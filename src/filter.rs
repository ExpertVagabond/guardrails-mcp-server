use regex::Regex;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FilterResult {
    pub modified: bool,
    pub text: String,
    pub redactions: Vec<Redaction>,
}

#[derive(Debug, Serialize)]
pub struct Redaction {
    pub category: String,
    pub original_length: usize,
}

pub struct OutputFilter {
    secret_patterns: Vec<(&'static str, Regex)>,
    pii_patterns: Vec<(&'static str, Regex)>,
}

impl OutputFilter {
    pub fn new() -> Self {
        Self {
            secret_patterns: vec![
                ("AWS_KEY", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
                ("AWS_SECRET", Regex::new(r"(?i)aws[_\x2d]?secret[_\x2d]?access[_\x2d]?key\s*[=:]\s*\S+").unwrap()),
                ("GITHUB_TOKEN", Regex::new(r"gh[ps]_[A-Za-z0-9_]{36,}").unwrap()),
                ("GENERIC_API_KEY", Regex::new(r"(?i)(api[_\x2d]?key|apikey|secret[_\x2d]?key|access[_\x2d]?token)\s*[=:]\s*['\x22]?[\w\x2d]{20,}").unwrap()),
                ("JWT", Regex::new(r"eyJ[A-Za-z0-9_\x2d]+[.]eyJ[A-Za-z0-9_\x2d]+[.][A-Za-z0-9_\x2d]+").unwrap()),
                ("PRIVATE_KEY", Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
                ("SLACK_TOKEN", Regex::new(r"xox[bpras]-[A-Za-z0-9\x2d]+").unwrap()),
                ("ANTHROPIC_KEY", Regex::new(r"sk-ant-[A-Za-z0-9\x2d_]{20,}").unwrap()),
                ("OPENAI_KEY", Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap()),
            ],
            pii_patterns: vec![
                ("SSN", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
                ("CREDIT_CARD", Regex::new(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b").unwrap()),
                ("EMAIL", Regex::new(r"\b[A-Za-z0-9._%+\x2d]+@[A-Za-z0-9.\x2d]+[.][A-Za-z]{2,}\b").unwrap()),
                ("PHONE", Regex::new(r"\b(?:[+]1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()),
            ],
        }
    }

    pub fn filter(&self, text: &str) -> FilterResult {
        let mut result = text.to_string();
        let mut redactions = Vec::new();

        for (name, pat) in &self.secret_patterns {
            for mat in pat.find_iter(text) {
                redactions.push(Redaction {
                    category: name.to_string(),
                    original_length: mat.len(),
                });
            }
            let replacement = format!("[REDACTED_{}]", name);
            result = pat.replace_all(&result, replacement.as_str()).to_string();
        }

        let snapshot = result.clone();
        for (name, pat) in &self.pii_patterns {
            for mat in pat.find_iter(&snapshot) {
                redactions.push(Redaction {
                    category: name.to_string(),
                    original_length: mat.len(),
                });
            }
            let replacement = format!("[REDACTED_{}]", name);
            result = pat.replace_all(&result, replacement.as_str()).to_string();
        }

        FilterResult {
            modified: !redactions.is_empty(),
            text: result,
            redactions,
        }
    }
}
