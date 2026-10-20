//! Browser policy is deliberately separate from DNS policy: URLs and OS profiles
//! have no trustworthy representation in an ordinary DNS question.
use anyhow::{bail, ensure};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub terms: Vec<String>,
    pub threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRule {
    pub id: String,
    pub scope: String,
    pub target: String,
    pub priority: u32,
    pub kind: String,
    pub pattern: String,
    pub action: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPolicy {
    pub revision: i64,
    pub default_action: String,
    pub rules: Vec<BrowserRule>,
    pub categories: Vec<Category>,
}

#[derive(Clone, Debug, Serialize, FromRow)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub group_name: String,
    pub os: String,
    pub account_id: String,
    pub require_native: bool,
    pub revoked: bool,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub os: String,
    pub account_id: String,
    pub username: String,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub url: String,
    #[serde(default)]
    pub categories: Vec<String>,
    pub identity: Option<Identity>,
}

#[derive(Debug, Serialize)]
pub struct Verdict {
    pub action: String,
    pub url: String,
    pub reason: String,
    pub rule_id: Option<String>,
    pub categories: Vec<String>,
    pub revision: i64,
}

pub fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|s| s.ends_with('.'))
}

/// Strip common tracking parameters without discarding meaningful application parameters.
/// Fragments stay local to the extension; they are never needed for a network decision.
pub fn clean_url(raw: &str) -> anyhow::Result<Url> {
    ensure!(raw.len() <= 4096, "URL exceeds 4096 bytes");
    let mut url = Url::parse(raw)?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "Only HTTP and HTTPS destinations are supported"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URLs containing credentials are rejected"
    );
    canonical_path(&url)?;
    url.set_fragment(None);
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| {
            let k = k.to_ascii_lowercase();
            !k.starts_with("utm_")
                && !matches!(
                    k.as_str(),
                    "fbclid" | "gclid" | "dclid" | "msclkid" | "mc_cid" | "mc_eid"
                )
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    // Avoid re-encoding signed queries when no tracking parameter was removed.
    if pairs.len() != url.query_pairs().count() {
        url.set_query(None);
        if !pairs.is_empty() {
            url.query_pairs_mut().extend_pairs(pairs);
        }
    }
    Ok(url)
}

// Compare decoded path characters consistently. Encoded separators, nested escapes,
// and controls have server-dependent meanings and are rejected rather than guessed.
fn canonical_path(url: &Url) -> anyhow::Result<String> {
    let mut decoded = Vec::new();
    let mut bytes = url.path().bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let a = bytes.next().and_then(|b| (b as char).to_digit(16));
            let b = bytes.next().and_then(|b| (b as char).to_digit(16));
            let value = match (a, b) {
                (Some(a), Some(b)) => (a * 16 + b) as u8,
                _ => bail!("Invalid path escape"),
            };
            ensure!(
                !matches!(value, b'/' | b'\\' | b'%') && !value.is_ascii_control(),
                "Ambiguous encoded path separator or control"
            );
            decoded.push(value);
        } else {
            decoded.push(b);
        }
    }
    Ok(String::from_utf8(decoded)?)
}

pub fn category_matches(category: &Category, text: &str) -> bool {
    let text = text.to_lowercase();
    category
        .terms
        .iter()
        .filter(|term| {
            text.match_indices(term.as_str()).any(|(i, _)| {
                let before = text[..i].chars().next_back();
                let after = text[i + term.len()..].chars().next();
                !before.is_some_and(char::is_alphanumeric)
                    && !after.is_some_and(char::is_alphanumeric)
            })
        })
        .count()
        >= category.threshold
}

impl Default for BrowserPolicy {
    fn default() -> Self {
        Self {
            revision: 0,
            default_action: "allow".into(),
            rules: vec![],
            categories: vec![
                Category {
                    id: "adult".into(),
                    name: "Explicit adult content".into(),
                    domains: vec![],
                    terms: vec![
                        "pornography".into(),
                        "xxx".into(),
                        "adult videos".into(),
                        "explicit sex".into(),
                    ],
                    threshold: 2,
                },
                Category {
                    id: "gambling".into(),
                    name: "Gambling".into(),
                    domains: vec![],
                    terms: vec![
                        "online casino".into(),
                        "sports betting".into(),
                        "slot machines".into(),
                        "bet now".into(),
                    ],
                    threshold: 2,
                },
                Category {
                    id: "social".into(),
                    name: "Social networks".into(),
                    domains: vec![
                        "facebook.com".into(),
                        "instagram.com".into(),
                        "tiktok.com".into(),
                    ],
                    terms: vec![],
                    threshold: 1,
                },
                Category {
                    id: "unclassified".into(),
                    name: "Unclassified".into(),
                    domains: vec![],
                    terms: vec![],
                    threshold: 1,
                },
            ],
        }
    }
}

impl BrowserPolicy {
    pub async fn load(pool: &SqlitePool) -> anyhow::Result<Self> {
        let document: Option<String> =
            sqlx::query_scalar("SELECT document FROM browser_policy WHERE id=1")
                .fetch_optional(pool)
                .await?;
        match document {
            Some(document) => Ok(serde_json::from_str(&document)?),
            None => Ok(Self::default()),
        }
    }

    pub fn validate(&mut self) -> anyhow::Result<()> {
        ensure!(
            matches!(self.default_action.as_str(), "allow" | "block" | "sanitize"),
            "Invalid default action"
        );
        ensure!(
            self.rules.len() <= 500 && self.categories.len() <= 64,
            "Policy supports up to 500 rules and 64 categories"
        );
        let valid_id = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        let mut ids = BTreeSet::new();
        for category in &mut self.categories {
            ensure!(
                valid_id(&category.id) && ids.insert(category.id.clone()),
                "Category IDs must be unique letters, digits, underscores or hyphens"
            );
            ensure!(
                !category.name.is_empty()
                    && category.name.len() <= 80
                    && category.domains.len() <= 500
                    && category.terms.len() <= 50
                    && (1..=50).contains(&category.threshold),
                "Invalid category name, size or threshold"
            );
            for domain in &mut category.domains {
                *domain = crate::policy::normalize_domain(domain)?;
            }
            for term in &mut category.terms {
                *term = term.trim().to_lowercase();
                ensure!(
                    (2..=80).contains(&term.len()),
                    "Category terms must have 2–80 bytes"
                );
            }
            category.terms.sort();
            category.terms.dedup();
            ensure!(
                category.terms.is_empty() || category.threshold <= category.terms.len(),
                "Category threshold exceeds its distinct terms"
            );
            ensure!(
                category.id != "unclassified"
                    || (category.domains.is_empty() && category.terms.is_empty()),
                "Unclassified is reserved for pages with no category evidence"
            );
        }
        let mut rule_ids = BTreeSet::new();
        for rule in &mut self.rules {
            ensure!(
                valid_id(&rule.id) && rule_ids.insert(rule.id.clone()),
                "Rule IDs must be valid and unique"
            );
            ensure!(
                matches!(rule.action.as_str(), "allow" | "block" | "sanitize"),
                "Invalid rule action"
            );
            ensure!(
                rule.priority <= 100000 && rule.target.len() <= 80,
                "Invalid priority or scope target"
            );
            match rule.scope.as_str() {
                "global" => ensure!(rule.target.is_empty(), "Global rules have no target"),
                "group" => ensure!(
                    !rule.target.trim().is_empty(),
                    "Group rules require a group name"
                ),
                "profile" => ensure!(
                    rule.target.parse::<i64>().is_ok_and(|n| n > 0),
                    "Profile rules require a profile ID"
                ),
                _ => bail!("Invalid rule scope"),
            }
            match rule.kind.as_str() {
                "domain" => rule.pattern = crate::policy::normalize_domain(&rule.pattern)?,
                "path" => {
                    let url = clean_url(&rule.pattern)?;
                    ensure!(
                        url.query().is_none(),
                        "Path rules use an origin and path, without a query"
                    );
                    rule.pattern = url.to_string();
                }
                "category" => {
                    ensure!(ids.contains(&rule.pattern), "Unknown rule category");
                    ensure!(
                        rule.action != "allow",
                        "Category evidence can restrict access, but cannot authorize it; use an explicit domain or path allow"
                    );
                }
                "all" => ensure!(rule.pattern.is_empty(), "An all-pages rule has no pattern"),
                _ => bail!("Invalid rule matcher"),
            }
        }
        self.rules.sort_by(|a, b| {
            (scope_rank(&a.scope), a.priority, &a.id).cmp(&(
                scope_rank(&b.scope),
                b.priority,
                &b.id,
            ))
        });
        Ok(())
    }

    pub fn classify(&self, url: &Url, text: &str, hints: &[String]) -> Vec<String> {
        let host = url.host_str().unwrap_or_default();
        let mut found: Vec<String> = self
            .categories
            .iter()
            .filter(|c| {
                c.id != "unclassified"
                    && (c.domains.iter().any(|d| domain_matches(host, d))
                        || category_matches(c, text)
                        || hints.contains(&c.id))
            })
            .map(|c| c.id.clone())
            .collect();
        if found.is_empty() {
            found.push("unclassified".into());
        }
        found
    }

    pub fn decide(
        &self,
        profile: &Profile,
        input: &Check,
        dns: &crate::policy::Policy,
    ) -> anyhow::Result<Verdict> {
        ensure!(
            input.categories.len() <= 64 && input.categories.iter().all(|c| c.len() <= 64),
            "Too many category hints"
        );
        let url = clean_url(&input.url)?;
        let categories = self.classify(
            &url,
            &url.to_string().replace(['/', '-', '_', '.', '%'], " "),
            &input.categories,
        );
        let mut verdict = Verdict {
            action: self.default_action.clone(),
            url: url.to_string(),
            reason: "Organization default".into(),
            rule_id: None,
            categories,
            revision: self.revision,
        };
        if profile.revoked {
            verdict.action = "block".into();
            verdict.reason = "Profile revoked".into();
            return Ok(verdict);
        }
        if profile.require_native
            && !input
                .identity
                .as_ref()
                .is_some_and(|i| i.os == profile.os && i.account_id == profile.account_id)
        {
            verdict.action = "block".into();
            verdict.reason =
                "Desktop identity is missing or does not match the enrolled OS account".into();
            return Ok(verdict);
        }
        // DNS blocks are an organization-wide baseline. Browser rules cannot weaken it.
        let domain = dns.decide(url.host_str().unwrap_or_default());
        if domain.blocked {
            verdict.action = "block".into();
            verdict.reason = format!("DNS baseline: {}", domain.reason);
            return Ok(verdict);
        }
        for rule in &self.rules {
            if !rule.enabled
                || !(rule.scope == "global"
                    || (rule.scope == "group" && rule.target == profile.group_name)
                    || (rule.scope == "profile" && rule.target == profile.id.to_string()))
            {
                continue;
            }
            let matched = match rule.kind.as_str() {
                "all" => true,
                "domain" => domain_matches(url.host_str().unwrap_or_default(), &rule.pattern),
                "category" => verdict.categories.contains(&rule.pattern),
                "path" => {
                    let pattern = Url::parse(&rule.pattern)?;
                    let path = canonical_path(&url)?;
                    let pattern_path = canonical_path(&pattern)?;
                    let base = pattern_path.trim_end_matches('/');
                    url.origin() == pattern.origin()
                        && (path == base
                            || path.strip_prefix(base).is_some_and(|p| p.starts_with('/')))
                }
                _ => false,
            };
            if matched {
                verdict.action = rule.action.clone();
                verdict.rule_id = Some(rule.id.clone());
                verdict.reason = format!("{} rule {} ({})", rule.scope, rule.id, rule.kind);
                break;
            }
        }
        Ok(verdict)
    }
}

fn scope_rank(scope: &str) -> u8 {
    match scope {
        "global" => 0,
        "group" => 1,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_normalization_and_category_evidence() {
        assert!(clean_url("javascript:alert(1)").is_err());
        assert!(clean_url("https://user:pass@example.com/").is_err());
        assert!(clean_url("https://example.com/a%255cb").is_err());
        assert_eq!(
            clean_url("https://EXAMPLE.com/a?utm_source=x&q=keep#secret")
                .unwrap()
                .as_str(),
            "https://example.com/a?q=keep"
        );
        assert_eq!(
            clean_url("https://example.com/?signed=a%20b")
                .unwrap()
                .as_str(),
            "https://example.com/?signed=a%20b"
        );
        assert!(!domain_matches("example.com.evil.test", "example.com"));
        assert!(domain_matches("sub.example.com", "example.com"));
        let policy = BrowserPolicy::default();
        let category = &policy.categories[1];
        assert!(!category_matches(category, "online casino online casino"));
        assert!(category_matches(category, "Online Casino. BET NOW!"));
        assert!(!category_matches(category, "notonline casinos: bet nowish"));
    }
}
