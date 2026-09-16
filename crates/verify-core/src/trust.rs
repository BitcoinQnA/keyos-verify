use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::SignatureIdentity;

const MAX_PUBLISHERS: usize = 32;
const MAX_STORE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherDetails {
    pub name: String,
    pub email: String,
}

impl PublisherDetails {
    pub fn from_user_id(user_id: Option<&str>) -> Self {
        let value = user_id.unwrap_or("").trim();
        let (name, email) = match value.strip_suffix('>').and_then(|v| v.rsplit_once('<')) {
            Some((name, email)) => (name.trim().trim_matches('"'), email.trim()),
            None if value.contains('@') && !value.chars().any(char::is_whitespace) => ("", value),
            None => (value, ""),
        };
        Self {
            name: clean_text(name, 128),
            email: clean_text(email, 254),
        }
    }

    fn sanitized(self) -> Self {
        Self {
            name: clean_text(&self.name, 128),
            email: clean_text(&self.email, 254),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustStore {
    publishers: BTreeMap<String, Option<PublisherDetails>>,
    saved_keys: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    publishers: BTreeMap<String, Option<PublisherDetails>>,
    #[serde(default)]
    saved_keys: BTreeSet<String>,
}

impl TrustStore {
    /// Load versioned metadata or legacy newline-separated fingerprints; invalid stores grant no trust.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > MAX_STORE_BYTES {
            return Self::default();
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Self::default();
        };
        let (publishers, saved_keys) = if text.trim_start().starts_with('{') {
            let Ok(document) = serde_json::from_str::<Document>(text) else {
                return Self::default();
            };
            if !matches!(document.version, 1 | 2)
                || document.publishers.len() > MAX_PUBLISHERS
                || document.saved_keys.len() > MAX_PUBLISHERS
            {
                return Self::default();
            }
            let saved_keys = if document.version == 2 {
                document.saved_keys
            } else {
                BTreeSet::new()
            };
            (document.publishers, saved_keys)
        } else {
            (
                text.lines()
                    .filter(|line| valid_fingerprint(line))
                    .take(MAX_PUBLISHERS)
                    .map(|line| (line.to_owned(), None))
                    .collect(),
                BTreeSet::new(),
            )
        };
        if publishers.keys().any(|key| !valid_fingerprint(key))
            || saved_keys.iter().any(|key| !valid_fingerprint(key))
        {
            return Self::default();
        }
        let publishers = publishers
            .into_iter()
            .map(|(key, details)| {
                (
                    key.to_ascii_uppercase(),
                    details.map(PublisherDetails::sanitized),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Self {
            saved_keys: saved_keys
                .into_iter()
                .map(|key| key.to_ascii_uppercase())
                .filter(|key| publishers.contains_key(key))
                .collect(),
            publishers,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&Document {
            version: 2,
            publishers: self.publishers.clone(),
            saved_keys: self.saved_keys.clone(),
        })
        .map_err(|error| error.to_string())
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.publishers
            .contains_key(&fingerprint.to_ascii_uppercase())
    }

    pub fn entries(&self) -> impl Iterator<Item = (&String, &Option<PublisherDetails>)> {
        self.publishers.iter()
    }

    pub fn key_available(&self, fingerprint: &str) -> bool {
        self.saved_keys.contains(&fingerprint.to_ascii_uppercase())
    }

    /// Mark a complete public key as available only for an already trusted fingerprint.
    pub fn remember_key(&mut self, fingerprint: &str) -> bool {
        let fingerprint = fingerprint.to_ascii_uppercase();
        self.publishers.contains_key(&fingerprint) && self.saved_keys.insert(fingerprint)
    }

    /// Add a verified identity only after the user explicitly confirms its fingerprint.
    pub fn remember(&mut self, identity: &SignatureIdentity) -> Result<(), String> {
        if !valid_fingerprint(&identity.fingerprint) {
            // TODO: localize
            return Err("Invalid publisher fingerprint.".into());
        }
        if !self.contains(&identity.fingerprint) && self.publishers.len() >= MAX_PUBLISHERS {
            // TODO: localize
            return Err(
                "The 32-key limit has been reached. Forget saved keys before adding more.".into(),
            );
        }
        self.publishers.insert(
            identity.fingerprint.to_ascii_uppercase(),
            Some(PublisherDetails::from_user_id(identity.user_id.as_deref())),
        );
        Ok(())
    }

    /// Refresh display metadata after successful signature and artifact verification, without adding trust.
    pub fn refresh_details(&mut self, identity: &SignatureIdentity) -> bool {
        let Some(stored) = self
            .publishers
            .get_mut(&identity.fingerprint.to_ascii_uppercase())
        else {
            return false;
        };
        let details = PublisherDetails::from_user_id(identity.user_id.as_deref());
        if stored.as_ref() == Some(&details)
            || (stored.is_some() && details.name.is_empty() && details.email.is_empty())
        {
            return false;
        }
        *stored = Some(details);
        true
    }

    pub fn clear(&mut self) {
        self.publishers.clear();
        self.saved_keys.clear();
    }

    /// Remove only the exact fingerprint and its display metadata.
    pub fn forget(&mut self, fingerprint: &str) -> bool {
        let fingerprint = fingerprint.to_ascii_uppercase();
        self.saved_keys.remove(&fingerprint);
        self.publishers.remove(&fingerprint).is_some()
    }
}

fn valid_fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn clean_text(value: &str, limit: usize) -> String {
    value.chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .take(limit).collect::<String>().trim().to_owned()
}
