use crate::audit::AuditLogger;
use crate::filter::OutputFilter;
use crate::policy::PolicyEngine;
use crate::validator::InputValidator;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    pub enable_input_validation: bool,
    pub enable_output_filtering: bool,
    pub enable_policy_enforcement: bool,
    pub enable_rate_limiting: bool,
    pub max_requests_per_minute: usize,
    pub max_tokens_per_request: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_input_validation: true,
            enable_output_filtering: true,
            enable_policy_enforcement: true,
            enable_rate_limiting: true,
            max_requests_per_minute: 60,
            max_tokens_per_request: 100_000,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InputResult {
    pub allowed: bool,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub validation: Option<serde_json::Value>,
    pub policy: Option<serde_json::Value>,
    pub processing_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub active_users: usize,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub config: Config,
}

pub struct GuardrailsEngine {
    pub config: Config,
    validator: InputValidator,
    filter: OutputFilter,
    policy_engine: PolicyEngine,
    audit: AuditLogger,
    rate_limits: HashMap<String, Vec<Instant>>,
}

impl GuardrailsEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            validator: InputValidator::new(),
            filter: OutputFilter::new(),
            policy_engine: PolicyEngine::new(),
            audit: AuditLogger::new(),
            rate_limits: HashMap::new(),
        }
    }

    pub fn process_input(&mut self, text: &str, user_id: &str) -> InputResult {
        let start = Instant::now();
        let request_id = format!("gr_{}", uuid::Uuid::new_v4());

        // Rate limiting
        if self.config.enable_rate_limiting {
            if let Some(retry_after) = self.check_rate_limit(user_id) {
                self.audit.log("RATE_LIMIT_EXCEEDED", &format!("retry_after={retry_after}s"), user_id);
                return InputResult {
                    allowed: false,
                    request_id,
                    reason: Some(format!("Rate limit exceeded, retry after {retry_after}s")),
                    code: Some("RATE_LIMIT".into()),
                    validation: None,
                    policy: None,
                    processing_ms: start.elapsed().as_millis(),
                };
            }
        }

        // Input validation
        let validation = if self.config.enable_input_validation {
            let result = self.validator.validate(text, self.config.max_tokens_per_request);
            if !result.valid {
                self.audit.log("INPUT_BLOCKED", &format!("{} violations", result.violations.len()), user_id);
                let val = serde_json::to_value(&result).ok();
                return InputResult {
                    allowed: false,
                    request_id,
                    reason: Some("Input validation failed".into()),
                    code: Some("VALIDATION_ERROR".into()),
                    validation: val,
                    policy: None,
                    processing_ms: start.elapsed().as_millis(),
                };
            }
            serde_json::to_value(&result).ok()
        } else {
            None
        };

        // Policy enforcement
        let policy = if self.config.enable_policy_enforcement {
            let result = self.policy_engine.evaluate(text, None);
            if !result.allowed {
                self.audit.log("POLICY_VIOLATION", &format!("{} violations", result.violations.len()), user_id);
                let pol = serde_json::to_value(&result).ok();
                return InputResult {
                    allowed: false,
                    request_id,
                    reason: Some("Policy violation".into()),
                    code: Some("POLICY_VIOLATION".into()),
                    validation,
                    policy: pol,
                    processing_ms: start.elapsed().as_millis(),
                };
            }
            serde_json::to_value(&result).ok()
        } else {
            None
        };

        self.audit.log("INPUT_PROCESSED", "ok", user_id);

        InputResult {
            allowed: true,
            request_id,
            reason: None,
            code: None,
            validation,
            policy,
            processing_ms: start.elapsed().as_millis(),
        }
    }

    pub fn filter_output(&mut self, text: &str) -> serde_json::Value {
        if !self.config.enable_output_filtering {
            return serde_json::json!({ "modified": false, "text": text });
        }
        let result = self.filter.filter(text);
        self.audit.log("OUTPUT_FILTERED", &format!("{} redactions", result.redactions.len()), "system");
        serde_json::to_value(&result).unwrap_or_default()
    }

    pub fn check_policy(&self, text: &str, filter_names: Option<&[String]>) -> serde_json::Value {
        let result = self.policy_engine.evaluate(text, filter_names);
        serde_json::to_value(&result).unwrap_or_default()
    }

    pub fn get_audit_logs(&self, event_type: Option<&str>, limit: usize) -> serde_json::Value {
        let logs = self.audit.get_logs(event_type, limit);
        serde_json::to_value(&logs).unwrap_or_default()
    }

    pub fn get_stats(&self) -> Stats {
        Stats {
            active_users: self.rate_limits.len(),
            total_requests: self.audit.total_requests(),
            blocked_requests: self.audit.blocked_requests(),
            config: self.config.clone(),
        }
    }

    pub fn add_policy(&mut self, name: &str, pattern: &str, action: &str, desc: &str) -> Result<(), String> {
        self.policy_engine.add(name, pattern, action, desc)
    }

    pub fn remove_policy(&mut self, name: &str) -> bool {
        self.policy_engine.remove(name)
    }

    fn check_rate_limit(&mut self, user_id: &str) -> Option<u64> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(60);

        let requests = self.rate_limits.entry(user_id.to_string()).or_default();
        requests.retain(|t| now.duration_since(*t) < window);

        if requests.len() >= self.config.max_requests_per_minute {
            let oldest = requests.first().unwrap();
            let retry_after = (window - now.duration_since(*oldest)).as_secs() + 1;
            Some(retry_after)
        } else {
            requests.push(now);
            None
        }
    }
}
