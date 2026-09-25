use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::engine::EngineError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub allowed_domains: HashSet<String>,
    pub blocked_domains: HashSet<String>,
    pub max_requests_per_second: u32,
    pub allowed_ports: HashSet<u16>,
    pub sandbox_required: bool,
}

impl Policy {
    pub fn check_domain(&self, domain: &str) -> Result<(), EngineError> {
        if self.blocked_domains.contains(domain) {
            return Err(EngineError::PolicyViolation(format!(
                "domain {domain} is blocked"
            )));
        }
        if self.allowed_domains.is_empty() {
            return Err(EngineError::PolicyViolation(
                "ALLOWED_DOMAINS is not configured. Set it via environment variable before scanning".to_string()
            ));
        }
        let allowed = self.allowed_domains.iter().any(|d| {
            d == domain || (d.starts_with("*.") && domain.ends_with(&d[1..]))
        });
        if !allowed {
            return Err(EngineError::PolicyViolation(format!(
                "domain {domain} not in ALLOWED_DOMAINS"
            )));
        }
        Ok(())
    }

    pub fn check_port(&self, port: u16) -> Result<(), EngineError> {
        if !self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port) {
            return Err(EngineError::PolicyViolation(format!(
                "port {port} not allowed"
            )));
        }
        Ok(())
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_domains: HashSet::new(),
            blocked_domains: HashSet::new(),
            max_requests_per_second: 50,
            allowed_ports: [80, 443, 8080, 8443].into_iter().collect(),
            sandbox_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_allowlist() {
        let policy = Policy {
            allowed_domains: ["*.example.com".into()].into(),
            ..Default::default()
        };
        assert!(policy.check_domain("sub.example.com").is_ok());
        assert!(policy.check_domain("evil.com").is_err());
    }

    #[test]
    fn domain_blocklist() {
        let policy = Policy {
            blocked_domains: ["internal.corp".into()].into(),
            ..Default::default()
        };
        assert!(policy.check_domain("internal.corp").is_err());
        assert!(policy.check_domain("public.com").is_ok());
    }

    #[test]
    fn port_enforcement() {
        let policy = Policy::default();
        assert!(policy.check_port(443).is_ok());
        assert!(policy.check_port(22).is_err());
    }
}
