use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Policy {
    pub name: String,
    pub description: String,
    pub action: PolicyAction,
    #[serde(skip)]
    pub pattern: Regex,
    pub pattern_str: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Block,
    Warn,
    Redact,
}

#[derive(Debug, Serialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub violations: Vec<PolicyViolation>,
    pub warnings: Vec<PolicyViolation>,
}

#[derive(Debug, Serialize)]
pub struct PolicyViolation {
    pub policy: String,
    pub action: PolicyAction,
    pub description: String,
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut engine = Self { policies: Vec::new() };
        engine.add_defaults();
        engine
    }

    fn add_defaults(&mut self) {
        let defaults: Vec<(&str, &str, &str, &str)> = vec![
            ("no_secrets_in_output", r"(?i)(password|passwd|secret)\s*[=:]\s*\S+", "block", "Block password/secret exposure"),
            ("no_sql_injection", r"(?i)(union\s+select|;\s*drop\s+table|'\s*or\s+'1'\s*=\s*'1)", "block", "Block SQL injection patterns"),
            ("no_path_traversal", r"[.][.]/[.][.]/", "block", "Block path traversal attempts"),
            ("no_xxe", r"(?i)<[!]ENTITY|<[!]DOCTYPE.*\[", "block", "Block XXE injection"),
            ("no_command_injection", r"(?i);\s*(cat|ls|whoami|id|uname)\b", "warn", "Warn on command injection"),
        ];

        for (name, pattern, action, desc) in defaults {
            let _ = self.add(name, pattern, action, desc);
        }
    }

    pub fn add(&mut self, name: &str, pattern: &str, action: &str, description: &str) -> Result<(), String> {
        let regex = Regex::new(pattern).map_err(|e| format!("invalid regex: {}", e))?;
        let action = match action {
            "block" => PolicyAction::Block,
            "warn" => PolicyAction::Warn,
            "redact" => PolicyAction::Redact,
            _ => return Err(format!("invalid action: {} (use block/warn/redact)", action)),
        };

        self.policies.retain(|p| p.name != name);

        self.policies.push(Policy {
            name: name.into(),
            description: description.into(),
            action,
            pattern: regex,
            pattern_str: pattern.into(),
        });

        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.name != name);
        self.policies.len() < before
    }

    pub fn evaluate(&self, text: &str, filter_names: Option<&[String]>) -> PolicyResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();
        let mut blocked = false;

        for policy in &self.policies {
            if let Some(names) = filter_names {
                if !names.iter().any(|n| n == &policy.name) {
                    continue;
                }
            }

            if policy.pattern.is_match(text) {
                let violation = PolicyViolation {
                    policy: policy.name.clone(),
                    action: policy.action.clone(),
                    description: policy.description.clone(),
                };

                match policy.action {
                    PolicyAction::Block => {
                        blocked = true;
                        violations.push(violation);
                    }
                    PolicyAction::Warn => warnings.push(violation),
                    PolicyAction::Redact => violations.push(violation),
                }
            }
        }

        PolicyResult {
            allowed: !blocked,
            violations,
            warnings,
        }
    }

    pub fn list(&self) -> Vec<&Policy> {
        self.policies.iter().collect()
    }
}
