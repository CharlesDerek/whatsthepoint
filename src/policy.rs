use anyhow::{Context, bail};
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct Rule {
    pub id: i64,
    pub domain: String,
    pub action: String,
    pub note: String,
    pub created_at: i64,
}

#[derive(Default)]
pub struct Policy {
    pub rules: HashMap<String, Rule>,
    pub domains: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct Decision {
    pub blocked: bool,
    pub reason: String,
    pub matched: Option<String>,
}

pub fn normalize_domain(input: &str) -> anyhow::Result<String> {
    let input = input.trim().trim_end_matches('.');
    let input = input.strip_prefix("*.").unwrap_or(input);
    let ascii = idna::domain_to_ascii(input)
        .map_err(|_| anyhow::anyhow!("invalid international domain"))?
        .to_lowercase();
    if ascii.len() > 253
        || !ascii.contains('.')
        || ascii.parse::<std::net::IpAddr>().is_ok()
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        bail!("enter a domain such as example.com, without a URL, port, or path");
    }
    Ok(ascii)
}

impl Policy {
    pub async fn load(pool: &SqlitePool) -> anyhow::Result<Self> {
        let rules = sqlx::query_as::<_, Rule>("SELECT * FROM rules")
            .fetch_all(pool)
            .await?;
        let domains: Vec<(String, String)> = sqlx::query_as(
            "SELECT domain, min(name) FROM list_domains JOIN lists ON lists.id = list_id GROUP BY domain"
        ).fetch_all(pool).await?;
        Ok(Self {
            rules: rules.into_iter().map(|r| (r.domain.clone(), r)).collect(),
            domains: domains.into_iter().collect(),
        })
    }

    pub fn decide(&self, domain: &str) -> Decision {
        let name = domain.trim_end_matches('.').to_ascii_lowercase();
        let suffixes: Vec<&str> = std::iter::successors(Some(name.as_str()), |s| {
            s.split_once('.').map(|(_, rest)| rest)
        })
        .collect();
        // Explicit allow rules win at any ancestor. Most-specific rule explains the result.
        for suffix in &suffixes {
            if let Some(rule) = self.rules.get(*suffix).filter(|r| r.action == "allow") {
                return Decision {
                    blocked: false,
                    reason: "Allow rule".into(),
                    matched: Some(rule.domain.clone()),
                };
            }
        }
        for suffix in suffixes {
            if let Some(rule) = self.rules.get(suffix).filter(|r| r.action == "block") {
                return Decision {
                    blocked: true,
                    reason: "Block rule".into(),
                    matched: Some(rule.domain.clone()),
                };
            }
            if let Some(list) = self.domains.get(suffix) {
                return Decision {
                    blocked: true,
                    reason: list.clone(),
                    matched: Some(suffix.into()),
                };
            }
        }
        Decision {
            blocked: false,
            reason: "No blocking rule".into(),
            matched: None,
        }
    }
}

// Intentionally accepts only hosts files and one-domain-per-line lists, not adblock expressions.
pub fn parse_list(text: &str) -> anyhow::Result<Vec<String>> {
    let mut domains = BTreeSet::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        let names = if parts[0].parse::<std::net::IpAddr>().is_ok() {
            if !matches!(parts[0], "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
                bail!("unsupported hosts address on line {}", line_no + 1);
            }
            &parts[1..]
        } else {
            &parts[..]
        };
        if names.is_empty() || (names.len() > 1 && names.len() == parts.len()) {
            bail!("invalid entry on line {}", line_no + 1);
        }
        for name in names {
            if matches!(
                *name,
                "localhost"
                    | "localhost.localdomain"
                    | "ip6-localhost"
                    | "ip6-loopback"
                    | "broadcasthost"
            ) {
                continue;
            }
            domains.insert(
                normalize_domain(name)
                    .with_context(|| format!("invalid domain on line {}", line_no + 1))?,
            );
        }
        if domains.len() > 500_000 {
            bail!("blocklist exceeds 500,000 unique domains");
        }
    }
    if domains.is_empty() {
        bail!("blocklist has no usable domains; existing protection was kept");
    }
    Ok(domains.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_and_validation() {
        assert_eq!(
            normalize_domain("*.BÜCHER.de.").unwrap(),
            "xn--bcher-kva.de"
        );
        for bad in [
            "https://example.com",
            "a..com",
            "-a.com",
            "x.com:80",
            "127.0.0.1",
            "*",
            "com",
            "a.com/path",
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn boundary_and_allow_precedence() {
        let mut policy = Policy::default();
        policy
            .domains
            .insert("example.com".into(), "Test feed".into());
        assert!(policy.decide("a.EXAMPLE.com.").blocked);
        assert!(!policy.decide("notexample.com").blocked);
        assert!(!policy.decide("example.com.evil.net").blocked);
        policy.rules.insert(
            "safe.example.com".into(),
            Rule {
                id: 1,
                domain: "safe.example.com".into(),
                action: "allow".into(),
                note: String::new(),
                created_at: 0,
            },
        );
        assert!(!policy.decide("a.safe.example.com").blocked);
        assert!(policy.decide("other.example.com").blocked);
    }
    #[test]
    fn imports_are_strict_and_deduplicated() {
        assert_eq!(
            parse_list(
                "# comment\n0.0.0.0 ads.example ads2.example\nADS.example\n127.0.0.1 localhost"
            )
            .unwrap()
            .len(),
            2
        );
        for bad in [
            "",
            "<html>broken</html>",
            "||ads.example^",
            "good.example\nbroken",
            "192.168.1.1 router.example",
        ] {
            assert!(parse_list(bad).is_err());
        }
    }
}
