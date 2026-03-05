use regex::Regex;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub sanitized: String,
    pub violations: Vec<Violation>,
}

#[derive(Debug, Serialize)]
pub struct Violation {
    pub category: String,
    pub description: String,
    pub severity: String,
}

pub struct InputValidator {
    injection_patterns: Vec<(Regex, &'static str)>,
    code_patterns: Vec<(Regex, &'static str)>,
    pii_patterns: Vec<(&'static str, Regex)>,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            injection_patterns: vec![
                (Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)").unwrap(), "Prompt injection: ignore previous instructions"),
                (Regex::new(r"(?i)disregard\s+(all\s+)?(previous|prior|above)").unwrap(), "Prompt injection: disregard previous"),
                (Regex::new(r"(?i)forget\s+(everything|all|your)\s+(you|instructions?|rules?)").unwrap(), "Prompt injection: forget instructions"),
                (Regex::new(r"(?i)you\s+are\s+now\s+(a|an|the)\s+").unwrap(), "Prompt injection: role override"),
                (Regex::new(r"(?i)pretend\s+(you\s+are|to\s+be)").unwrap(), "Prompt injection: pretend"),
                (Regex::new(r"(?i)jailbreak").unwrap(), "Prompt injection: jailbreak"),
                (Regex::new(r"(?i)DAN\s+mode").unwrap(), "Prompt injection: DAN mode"),
                (Regex::new(r"(?i)developer\s+mode\s+(enabled|on|activated)").unwrap(), "Prompt injection: developer mode"),
                (Regex::new(r"(?i)bypass\s+(safety|security|filters?|guardrails?)").unwrap(), "Prompt injection: bypass safety"),
                (Regex::new(r"(?i)override\s+(system|safety|security)").unwrap(), "Prompt injection: override system"),
                (Regex::new(r"(?i)\[SYSTEM\]|\[ADMIN\]|\[ROOT\]").unwrap(), "Prompt injection: fake system tag"),
            ],
            code_patterns: vec![
                (Regex::new(r"(?i)eval\s*\(").unwrap(), "Malicious code: eval()"),
                (Regex::new(r"(?i)exec\s*\(").unwrap(), "Malicious code: exec()"),
                (Regex::new(r"(?i)system\s*\(").unwrap(), "Malicious code: system()"),
                (Regex::new(r"(?i)subprocess").unwrap(), "Malicious code: subprocess"),
                (Regex::new(r"(?i)child_process").unwrap(), "Malicious code: child_process"),
                (Regex::new(r";\s*rm\s+-rf").unwrap(), "Malicious code: rm -rf"),
                (Regex::new(r"&&\s*rm\s+-rf").unwrap(), "Malicious code: rm -rf"),
                (Regex::new(r"[|]\s*sh\b").unwrap(), "Malicious code: pipe to shell"),
            ],
            pii_patterns: vec![
                ("SSN", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
                ("CreditCard", Regex::new(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b").unwrap()),
                ("Email", Regex::new(r"\b[A-Za-z0-9._%+\x2d]+@[A-Za-z0-9.\x2d]+[.][A-Za-z]{2,}\b").unwrap()),
                ("Phone", Regex::new(r"\b(?:[+]1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()),
                ("IPAddress", Regex::new(r"\b(?:\d{1,3}[.]){3}\d{1,3}\b").unwrap()),
            ],
        }
    }

    pub fn validate(&self, text: &str, max_tokens: usize) -> ValidationResult {
        let mut violations = Vec::new();

        if text.len() > max_tokens * 4 {
            violations.push(Violation {
                category: "LENGTH".into(),
                description: format!("Input exceeds max length ({} > {})", text.len(), max_tokens * 4),
                severity: "high".into(),
            });
        }

        for (pat, desc) in &self.injection_patterns {
            if pat.is_match(text) {
                violations.push(Violation {
                    category: "INJECTION".into(),
                    description: desc.to_string(),
                    severity: "critical".into(),
                });
            }
        }

        for (pat, desc) in &self.code_patterns {
            if pat.is_match(text) {
                violations.push(Violation {
                    category: "MALICIOUS_CODE".into(),
                    description: desc.to_string(),
                    severity: "high".into(),
                });
            }
        }

        for (name, pat) in &self.pii_patterns {
            if pat.is_match(text) {
                violations.push(Violation {
                    category: "PII".into(),
                    description: format!("Detected {} in input", name),
                    severity: "medium".into(),
                });
            }
        }

        let valid = violations.is_empty();
        let sanitized = self.sanitize(text);

        ValidationResult { valid, sanitized, violations }
    }

    fn sanitize(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (name, pat) in &self.pii_patterns {
            let replacement = format!("[REDACTED_{}]", name);
            result = pat.replace_all(&result, replacement.as_str()).to_string();
        }
        result
    }
}
