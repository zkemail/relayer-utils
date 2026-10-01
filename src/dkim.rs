//! DKIM signature selection, public-key lookup and verification.
//!
//! REASON: the previous lookup (`fetch_public_keys` + `fetch_public_key_and_verify`) had
//! several independent problems, each covered by a test below:
//!  - `cfdkim::verify_email_with_key` returns `Ok(DKIMResult)` with a `fail`/`neutral` summary
//!    when no signature matches the domain or a signature header is invalid, and the caller
//!    treated any `Ok` as "verified". It was also called with the From: domain, so the
//!    subdomain / gappssmtp.com fallbacks (where `d=` differs from the From: domain) never
//!    verified anything.
//!  - Only one `(d=, s=)` pair was tried (a `HashMap` keyed by domain, so a second selector of
//!    the same domain was dropped, and the pick among several matches was random).
//!  - `DKIM-Signature` / `From` were looked up with exact header-name case.
//!  - `d=` / `s=` were read with `d=([^;]+);`, which also matches inside other tags and keeps
//!    folding whitespace.
//!  - The From: domain was taken from the last `@` in the field (comments / quoted display
//!    names confuse that).
//!  - Keys came only from the archive; a 429 from it was a hard error and DNS was never asked.
//!  - The canonicalized header/body/signature came from the FIRST DKIM-Signature
//!    (`cfdkim::canonicalize_signed_email`), not from the signature whose key was returned.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use cfdkim::{canonicalize_verified_signed_email, validate_header, DkimPublicKey};
use mailparse::ParsedMail;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use std::future::Future;

pub const DKIM_ARCHIVE_API_URL: &str = "https://archive.zk.email/api/key/domain";
pub const GOOGLE_DOH_URL: &str = "https://dns.google/resolve";

const GAPPS_DOMAIN: &str = "gappssmtp.com";

// NOTE: the archive allows 10 requests/min per IP. One retry after the server's
// retryAfterSeconds is attempted only when that wait is short.
#[cfg(not(target_arch = "wasm32"))]
const MAX_ARCHIVE_RETRY_WAIT_SECS: u64 = 15;

/// A DKIM-Signature that verified, with everything a circuit input needs from it.
#[derive(Debug, Clone)]
pub struct VerifiedDkim {
    /// `d=` of the verified signature
    pub domain: String,
    /// `s=` of the verified signature
    pub selector: String,
    /// RSA modulus (big-endian) of the key that verified it
    pub public_key: Vec<u8>,
    /// canonicalized header of the verified signature
    pub canonicalized_header: Vec<u8>,
    /// canonicalized body
    pub canonicalized_body: Vec<u8>,
    /// signature bytes (`b=`, decoded)
    pub signature: Vec<u8>,
}

/// Candidate keys (base64 `p=` values) for one selector.
#[derive(Debug, Clone, Default)]
pub struct KeyCandidates {
    pub keys: Vec<String>,
    /// Set when a key source failed (e.g. archive rate limit); a later "no key verified"
    /// error then says so instead of looking like a bad signature.
    pub errors: Vec<String>,
}

/// Where keys come from. `with_archive = false` must not touch the archive.
pub trait KeyResolver {
    fn resolve(
        &self,
        domain: &str,
        selector: &str,
        with_archive: bool,
    ) -> impl Future<Output = KeyCandidates>;
}

/// Google DNS-over-HTTPS (works natively and in wasm), plus the zk.email key archive.
pub struct NetworkKeyResolver;

impl KeyResolver for NetworkKeyResolver {
    async fn resolve(&self, domain: &str, selector: &str, with_archive: bool) -> KeyCandidates {
        let client = reqwest::Client::new();
        let mut out = KeyCandidates::default();
        if with_archive {
            match fetch_archive_keys(&client, DKIM_ARCHIVE_API_URL, domain, selector).await {
                Ok(keys) => out.keys = keys,
                Err(e) => out.errors.push(format!("archive: {e}")),
            }
        } else {
            match fetch_doh_keys(&client, GOOGLE_DOH_URL, domain, selector).await {
                Ok(keys) => out.keys = keys,
                Err(e) => out.errors.push(format!("dns: {e}")),
            }
        }
        out
    }
}

/// Verify `raw_email` and return the verified signature's key and canonicalization.
///
/// Every DKIM-Signature whose `d=` is the From: domain, a subdomain of it, or a
/// `*.gappssmtp.com` domain is tried (aligned ones first, header order). For each, the DNS key
/// is tried first; the archive (rate limited) only if no DNS key verified any signature.
pub async fn verify_dkim<R: KeyResolver>(
    raw_email: &[u8],
    ignore_body_hash: bool,
    resolver: &R,
) -> Result<VerifiedDkim> {
    let parsed = mailparse::parse_mail(raw_email)?;
    let from_domain = from_domain(&parsed)?;
    let candidates = dkim_signature_candidates(&parsed, &from_domain);
    if candidates.is_empty() {
        return Err(anyhow!(
            "No DKIM signature found for sender domain '{}'",
            from_domain
        ));
    }

    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let mut errors = Vec::new();
    // REASON: DNS first, archive second: the archive allows 10 requests/min per IP, so it is
    // only asked when the current DNS keys verified nothing (e.g. a rotated key).
    for with_archive in [false, true] {
        for (domain, selector) in &candidates {
            let found = resolver.resolve(domain, selector, with_archive).await;
            errors.extend(found.errors);
            for p in &found.keys {
                let Ok(key) = create_dkim_public_key(p) else {
                    continue;
                };
                let modulus = match &key {
                    DkimPublicKey::Rsa(k) => k.n().to_bytes_be(),
                    // NOTE: the circuits are RSA only.
                    DkimPublicKey::Ed25519(_) => continue,
                };
                if let Ok((header, body, signature)) = canonicalize_verified_signed_email(
                    &logger,
                    raw_email,
                    domain,
                    key,
                    ignore_body_hash,
                ) {
                    return Ok(VerifiedDkim {
                        domain: domain.clone(),
                        selector: selector.clone(),
                        public_key: modulus,
                        canonicalized_header: header,
                        canonicalized_body: body,
                        signature,
                    });
                }
            }
        }
    }

    let tried = candidates
        .iter()
        .map(|(d, s)| format!("{s}._domainkey.{d}"))
        .collect::<Vec<_>>()
        .join(", ");
    let note = if errors.is_empty() {
        String::new()
    } else {
        format!(" ({})", errors.join("; "))
    };
    Err(anyhow!(
        "Failed to verify email with any public key for {}{}",
        tried,
        note
    ))
}

/// `(d=, s=)` of every well-formed DKIM-Signature that may be used for `from_domain`, in the
/// order they should be tried: aligned with the From: domain first, then gappssmtp.com.
pub fn dkim_signature_candidates(parsed: &ParsedMail, from_domain: &str) -> Vec<(String, String)> {
    let mut aligned = Vec::new();
    let mut gapps = Vec::new();
    for header in &parsed.headers {
        // REASON: header field names are case-insensitive ("DKIM-Signature",
        // "Dkim-Signature", "dkim-signature" all occur).
        if !header.get_key_ref().eq_ignore_ascii_case("dkim-signature") {
            continue;
        }
        // NOTE: cfdkim's tag-list parser handles folded values (d=/s= on a later line,
        // whitespace around '=' and ';').
        let Ok(tags) = validate_header(&String::from_utf8_lossy(header.get_value_raw())) else {
            continue;
        };
        let domain = tags.get_required_tag("d").to_ascii_lowercase();
        let selector = tags.get_required_tag("s");
        let pair = (domain.clone(), selector);
        let list = if domain == from_domain || domain.ends_with(&format!(".{from_domain}")) {
            &mut aligned
        } else if domain == GAPPS_DOMAIN || domain.ends_with(&format!(".{GAPPS_DOMAIN}")) {
            &mut gapps
        } else {
            continue;
        };
        if !list.contains(&pair) {
            list.push(pair);
        }
    }
    aligned.extend(gapps);
    aligned
}

/// Domain of the single From: address, parsed like RFC 5322: comments and quoted display
/// names are skipped and the last `<angle-addr>` wins. Several From: fields are an error.
pub fn from_domain(parsed: &ParsedMail) -> Result<String> {
    let froms: Vec<String> = parsed
        .headers
        .iter()
        .filter(|h| h.get_key_ref().eq_ignore_ascii_case("from"))
        .map(|h| h.get_value())
        .collect();
    if froms.len() != 1 {
        return Err(anyhow!(
            "Expected exactly one From header, found {}",
            froms.len()
        ));
    }
    let address = address_from_field_value(&froms[0]);
    let domain = address
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let valid = domain.contains('.')
        && domain
            .split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !valid {
        return Err(anyhow!(
            "Could not extract domain from From header: {}",
            froms[0]
        ));
    }
    Ok(domain)
}

/// Address part of a From:/To: value: the last `<...>` outside quotes and comments, else the
/// whole value with quoted strings and comments removed.
pub fn address_from_field_value(value: &str) -> String {
    let mut outside = String::new();
    let mut angle: Option<String> = None;
    let mut current: Option<String> = None;
    let mut quoted = false;
    let mut comment = 0usize;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        if comment > 0 {
            match c {
                '\\' => {
                    chars.next();
                }
                '(' => comment += 1,
                ')' => comment -= 1,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '(' => comment = 1,
            '<' => current = Some(String::new()),
            '>' if current.is_some() => angle = current.take(),
            _ => match current.as_mut() {
                Some(cur) => cur.push(c),
                None => outside.push(c),
            },
        }
    }
    angle.unwrap_or(outside).trim().to_string()
}

/// Value of tag `name` in a DKIM tag-list (TXT record or signature), folding whitespace removed.
pub fn dkim_tag(tag_list: &str, name: &str) -> Option<String> {
    tag_list.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == name).then(|| v.chars().filter(|c| !c.is_whitespace()).collect())
    })
}

/// One header field in a canonicalized header block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFieldSpan {
    /// index of the first byte of the field name
    pub start: usize,
    /// index just after the ':'
    pub value_start: usize,
    /// index of the CRLF ending the field (or the end of the header); folds are inside
    pub end: usize,
}

/// Fields of a header block (CRLF separated, CRLF + SP/HTAB is a fold) whose name equals
/// `name` ignoring ASCII case, in order.
///
/// REASON: header lookups used to search for "name:" anywhere, so "to" matched inside
/// "in-reply-to:" / "reply-to:", "dkim-signature" inside "x-google-dkim-signature:", and text
/// inside another field's value could be picked. Only a name at the start of a field counts.
pub fn header_field_spans(header: &str, name: &str) -> Vec<HeaderFieldSpan> {
    let bytes = header.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        // end of this field: a CRLF (or LF) not followed by SP/HTAB
        let mut end = start;
        loop {
            match header[end..].find('\n') {
                None => {
                    end = bytes.len();
                    break;
                }
                Some(off) => {
                    let lf = end + off;
                    if matches!(bytes.get(lf + 1), Some(b' ') | Some(b'\t')) {
                        end = lf + 1;
                        continue;
                    }
                    end = if lf > 0 && bytes[lf - 1] == b'\r' { lf - 1 } else { lf };
                    break;
                }
            }
        }
        let field = &header[start..end];
        if let Some(colon) = field.find(':') {
            if field[..colon].trim_end().eq_ignore_ascii_case(name) {
                out.push(HeaderFieldSpan {
                    start,
                    value_start: start + colon + 1,
                    end,
                });
            }
        }
        // skip the line break
        start = match header[end..].find('\n') {
            Some(off) => end + off + 1,
            None => bytes.len(),
        };
    }
    out
}

/// Byte range of tag `tag`'s value in the LAST DKIM-Signature field of a canonicalized header
/// (the signature being verified is always the last field), surrounding whitespace excluded.
///
/// REASON: `bh=` / `t=` used to be found with an unanchored regex over the whole header, so an
/// earlier field (e.g. a Subject containing "bh=" or "set=5;") could be picked instead.
pub fn dkim_tag_range(canonicalized_header: &str, tag: &str) -> Option<(usize, usize)> {
    let field = *header_field_spans(canonicalized_header, "dkim-signature").last()?;
    let value = &canonicalized_header[field.value_start..field.end];
    let mut offset = field.value_start;
    for part in value.split(';') {
        if let Some(eq) = part.find('=') {
            if part[..eq].trim() == tag {
                let raw = &part[eq + 1..];
                let lead = raw.len() - raw.trim_start().len();
                let start = offset + eq + 1 + lead;
                return Some((start, start + raw.trim().len()));
            }
        }
        offset += part.len() + 1;
    }
    None
}

fn create_dkim_public_key(public_key_b64: &str) -> Result<DkimPublicKey> {
    let der = general_purpose::STANDARD.decode(public_key_b64)?;
    // Try SubjectPublicKeyInfo first, then PKCS#1.
    let key = RsaPublicKey::from_public_key_der(&der).or_else(|_| RsaPublicKey::from_pkcs1_der(&der))?;
    Ok(DkimPublicKey::Rsa(key))
}

/// Base64 `p=` values from a list of DKIM TXT records; revoked (empty `p=`) records dropped.
fn p_values<'a>(records: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for record in records {
        if let Some(p) = dkim_tag(record, "p").filter(|p| !p.is_empty()) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// Archived keys for `selector` at `domain`, most recently seen first.
pub async fn fetch_archive_keys(
    client: &reqwest::Client,
    api_url: &str,
    domain: &str,
    selector: &str,
) -> Result<Vec<String>> {
    #[cfg(not(target_arch = "wasm32"))]
    let mut retried = false;
    let body: serde_json::Value = loop {
        let resp = client
            .get(api_url)
            .query(&[("domain", domain), ("selector", selector)])
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            break serde_json::from_str(&text)?;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // NOTE: no sleep primitive is available in the wasm build without extra
            // dependencies, so the retry is native-only; wasm callers get the clear error.
            #[cfg(not(target_arch = "wasm32"))]
            {
                let wait = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.pointer("/details/retryAfterSeconds")?.as_u64());
                if !retried {
                    if let Some(wait) = wait.filter(|w| *w <= MAX_ARCHIVE_RETRY_WAIT_SECS) {
                        retried = true;
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                        continue;
                    }
                }
            }
            return Err(anyhow!(
                "DKIM key archive rate limit (10 requests/min per IP); retry in a minute"
            ));
        }
        return Err(anyhow!("DKIM key archive HTTP {}: {}", status, text));
    };

    let mut records: Vec<&serde_json::Value> = body
        .as_array()
        .ok_or_else(|| anyhow!("DKIM key archive response is not an array"))?
        .iter()
        // The endpoint already filters by selector; keep records that say otherwise out.
        .filter(|r| {
            r.get("selector")
                .and_then(|s| s.as_str())
                .map_or(true, |s| s == selector)
        })
        .collect();
    // ISO-8601 timestamps sort lexicographically; records without one go last.
    records.sort_by(|a, b| {
        let t = |r: &serde_json::Value| r.get("lastSeenAt").and_then(|t| t.as_str()).map(str::to_owned);
        t(b).cmp(&t(a))
    });
    Ok(p_values(
        records
            .iter()
            .filter_map(|r| r.get("value").and_then(|v| v.as_str())),
    ))
}

/// Current key(s) for `selector._domainkey.domain` from a DNS-over-HTTPS JSON API.
pub async fn fetch_doh_keys(
    client: &reqwest::Client,
    doh_url: &str,
    domain: &str,
    selector: &str,
) -> Result<Vec<String>> {
    let name = format!("{selector}._domainkey.{domain}");
    let body: serde_json::Value = client
        .get(doh_url)
        .query(&[("name", name.as_str()), ("type", "TXT")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let records: Vec<String> = body
        .get("Answer")
        .and_then(|a| a.as_array())
        .map(|answers| {
            answers
                .iter()
                // 16 = TXT (a CNAME chain also appears in Answer)
                .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(16))
                .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
                // NOTE: long TXT records come back as several quoted strings; join them.
                .map(|d| d.replace("\" \"", "").replace('"', ""))
                .collect()
        })
        .unwrap_or_default();
    Ok(p_values(records.iter().map(String::as_str)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfdkim::{canonicalization, DkimPrivateKey, SignerBuilder};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;
    use std::collections::HashMap;

    /// In-memory resolver: (domain, selector, from_archive) -> p= values.
    #[derive(Default)]
    struct MapResolver {
        dns: HashMap<(String, String), Vec<String>>,
        archive: HashMap<(String, String), Vec<String>>,
        archive_error: Option<String>,
    }

    impl KeyResolver for MapResolver {
        async fn resolve(&self, domain: &str, selector: &str, with_archive: bool) -> KeyCandidates {
            let key = (domain.to_string(), selector.to_string());
            let map = if with_archive { &self.archive } else { &self.dns };
            KeyCandidates {
                keys: map.get(&key).cloned().unwrap_or_default(),
                errors: if with_archive {
                    self.archive_error.clone().into_iter().collect()
                } else {
                    vec![]
                },
            }
        }
    }

    fn new_key() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap()
    }

    fn p(key: &RsaPrivateKey) -> String {
        general_purpose::STANDARD.encode(key.to_public_key().to_public_key_der().unwrap().as_bytes())
    }

    fn sign(raw: &str, key: &RsaPrivateKey, domain: &str, selector: &str) -> String {
        let email = mailparse::parse_mail(raw.as_bytes()).unwrap();
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let header = SignerBuilder::new()
            .with_signed_headers(&["From", "Subject"])
            .unwrap()
            .with_private_key(DkimPrivateKey::Rsa(key.clone()))
            .with_header_canonicalization(canonicalization::Type::Relaxed)
            .with_body_canonicalization(canonicalization::Type::Relaxed)
            .with_selector(selector)
            .with_signing_domain(domain)
            .with_logger(&logger)
            .build()
            .unwrap()
            .sign(&email)
            .unwrap();
        format!("{header}\r\n{raw}")
    }

    const BASE: &str =
        "From: Alice <alice@example.com>\r\nSubject: hello\r\n\r\nHello there\r\n";

    fn dns(entries: &[(&str, &str, &RsaPrivateKey)]) -> MapResolver {
        let mut r = MapResolver::default();
        for (d, s, k) in entries {
            r.dns.insert((d.to_string(), s.to_string()), vec![p(k)]);
        }
        r
    }

    #[tokio::test]
    async fn unverifiable_email_is_rejected() {
        let key = new_key();
        let signed = sign(BASE, &key, "example.com", "s1");
        // Wrong key published for the selector.
        let resolver = dns(&[("example.com", "s1", &new_key())]);
        assert!(verify_dkim(signed.as_bytes(), true, &resolver).await.is_err());
        // Invalid signature header (v=2), real key published: must not "verify".
        let bad_version = signed.replacen("v=1;", "v=2;", 1);
        let resolver = dns(&[("example.com", "s1", &key)]);
        assert!(verify_dkim(bad_version.as_bytes(), true, &resolver)
            .await
            .is_err());
        // Header signature intact but body changed, with the body hash checked.
        let tampered = signed.replace("Hello there", "Goodbye");
        assert!(verify_dkim(tampered.as_bytes(), false, &resolver)
            .await
            .is_err());
        assert!(verify_dkim(signed.as_bytes(), false, &resolver).await.is_ok());
    }

    #[tokio::test]
    async fn subdomain_signature_is_actually_verified() {
        let key = new_key();
        let signed = sign(BASE, &key, "mail.example.com", "s1");
        let ok = verify_dkim(signed.as_bytes(), true, &dns(&[("mail.example.com", "s1", &key)]))
            .await
            .unwrap();
        assert_eq!(ok.domain, "mail.example.com");
        assert!(verify_dkim(
            signed.as_bytes(),
            true,
            &dns(&[("mail.example.com", "s1", &new_key())])
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn every_signature_and_selector_is_tried_and_canonicalization_matches_it() {
        let (k1, k2) = (new_key(), new_key());
        // Two signatures from the same domain with different selectors; only s2's key is
        // published. An ESP signature that doesn't verify sits on top.
        let both = sign(&sign(BASE, &k2, "example.com", "s2"), &k1, "example.com", "s1");
        let raw = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=esp.example; s=x;\r\n h=from:subject; bh=AAAA; b=AAAA\r\n{both}"
        );
        let got = verify_dkim(raw.as_bytes(), false, &dns(&[("example.com", "s2", &k2)]))
            .await
            .unwrap();
        assert_eq!((got.domain.as_str(), got.selector.as_str()), ("example.com", "s2"));
        assert_eq!(got.public_key, k2.to_public_key().n().to_bytes_be());
        let header = String::from_utf8(got.canonicalized_header).unwrap();
        assert!(header.contains("s=s2;"), "{}", header);
        assert!(!header.contains("esp.example"), "{}", header);
    }

    #[tokio::test]
    async fn rotated_key_falls_back_to_archive_and_reports_archive_errors() {
        let (old, new) = (new_key(), new_key());
        let signed = sign(BASE, &old, "example.com", "s1");
        let mut resolver = dns(&[("example.com", "s1", &new)]);
        resolver.archive_error = Some("archive: rate limit".into());
        let err = verify_dkim(signed.as_bytes(), true, &resolver)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("rate limit"), "{}", err);

        resolver.archive_error = None;
        resolver.archive.insert(
            ("example.com".into(), "s1".into()),
            vec![p(&new), p(&old)],
        );
        let got = verify_dkim(signed.as_bytes(), true, &resolver).await.unwrap();
        assert_eq!(got.public_key, old.to_public_key().n().to_bytes_be());
    }

    #[tokio::test]
    async fn lowercase_header_names_and_folded_tags() {
        let key = new_key();
        let signed = sign(BASE, &key, "example.com", "s1");
        // fold before s= and lowercase the field names
        let folded = signed
            .replacen("DKIM-Signature:", "dkim-signature:", 1)
            .replacen("; s=s1;", ";\r\n\ts = s1;", 1)
            .replacen("From:", "FROM:", 1);
        assert!(folded.contains("\r\n\ts = s1;"));
        let parsed = mailparse::parse_mail(folded.as_bytes()).unwrap();
        assert_eq!(
            dkim_signature_candidates(&parsed, "example.com"),
            vec![("example.com".to_string(), "s1".to_string())]
        );

        // Relaxed canonicalization lowercases field names, so this still verifies.
        let lowercase = signed
            .replacen("DKIM-Signature:", "dkim-signature:", 1)
            .replacen("From:", "FROM:", 1);
        let resolver = dns(&[("example.com", "s1", &key)]);
        assert!(verify_dkim(lowercase.as_bytes(), false, &resolver).await.is_ok());
    }

    #[test]
    fn from_domain_is_parsed_like_rfc5322() {
        let dom = |from: &str| {
            let raw = format!("From: {from}\r\nSubject: x\r\n\r\nbody\r\n");
            from_domain(&mailparse::parse_mail(raw.as_bytes()).unwrap())
        };
        assert_eq!(dom("\"ceo@esp.example\" <ceo@bank.example>").unwrap(), "bank.example");
        assert_eq!(dom("<ceo@bank.example> (via x@esp.example)").unwrap(), "bank.example");
        assert_eq!(dom("ceo@Bank.Example").unwrap(), "bank.example");
        assert_eq!(dom("Name (a@b.example) <c@d.example>").unwrap(), "d.example");
        assert!(dom("undisclosed").is_err());
        let two = "From: a@x.example\r\nFrom: b@y.example\r\n\r\nbody\r\n";
        assert!(from_domain(&mailparse::parse_mail(two.as_bytes()).unwrap()).is_err());
    }

    #[test]
    fn header_fields_are_matched_at_field_start_only() {
        let h = "in-reply-to:<a@b.example>\r\nsubject:re: to: x\r\nto:Bob <bob@c.example>\r\nx-google-dkim-signature:v=1; bh=XX;\r\ndkim-signature:v=1; d=c.example; bh=YY=; t=5; b=";
        let to = header_field_spans(h, "to");
        assert_eq!(to.len(), 1);
        assert_eq!(&h[to[0].start..to[0].end], "to:Bob <bob@c.example>");
        let (s, e) = dkim_tag_range(h, "bh").unwrap();
        assert_eq!(&h[s..e], "YY=");
        let (s, e) = dkim_tag_range(h, "t").unwrap();
        assert_eq!(&h[s..e], "5");
        assert!(dkim_tag_range(h, "x").is_none());

        // folded field (c=simple) stays one field
        let folded = "Subject: a bh=ZZ;\r\nDKIM-Signature: v=1; d=c.example;\r\n\tbh=QQ;\r\n b=";
        let f = header_field_spans(folded, "dkim-signature");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].end, folded.len());
        let (s, e) = dkim_tag_range(folded, "bh").unwrap();
        assert_eq!(&folded[s..e], "QQ");
    }

    #[tokio::test]
    async fn archive_429_is_retried_once_then_reported() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/api/key/domain");
            then.status(429)
                .json_body(serde_json::json!({"details": {"retryAfterSeconds": 1}}));
        });
        let err = fetch_archive_keys(
            &reqwest::Client::new(),
            &server.url("/api/key/domain"),
            "example.com",
            "s1",
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{}", err);
        mock.assert_hits(2);
    }

    #[tokio::test]
    async fn archive_keys_newest_first_and_doh_segments_joined() {
        use httpmock::prelude::*;
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/archive")
                .query_param("domain", "example.com")
                .query_param("selector", "s1");
            then.status(200).json_body(serde_json::json!([
                {"selector": "s1", "value": "v=DKIM1; p=OLD", "lastSeenAt": "2023-01-01T00:00:00Z"},
                {"selector": "s1", "value": "v=DKIM1; p=", "lastSeenAt": "2026-01-01T00:00:00Z"},
                {"selector": "s1", "value": "v=DKIM1; p=NEW", "lastSeenAt": "2025-01-01T00:00:00Z"},
                {"selector": "s9", "value": "v=DKIM1; p=OTHER", "lastSeenAt": "2025-06-01T00:00:00Z"}
            ]));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/doh")
                .query_param("name", "s1._domainkey.example.com");
            then.status(200).json_body(serde_json::json!({"Answer": [
                {"type": 5, "data": "s1.example.net."},
                {"type": 16, "data": "\"v=DKIM1; k=rsa; p=AB\" \"CD\""}
            ]}));
        });
        let client = reqwest::Client::new();
        assert_eq!(
            fetch_archive_keys(&client, &server.url("/archive"), "example.com", "s1")
                .await
                .unwrap(),
            vec!["NEW", "OLD"]
        );
        assert_eq!(
            fetch_doh_keys(&client, &server.url("/doh"), "example.com", "s1")
                .await
                .unwrap(),
            vec!["ABCD"]
        );
    }

    #[test]
    fn dkim_tag_parsing() {
        let rec = "v=DKIM1; k=rsa;\r\n p=AB CD\r\n\tEF;";
        assert_eq!(dkim_tag(rec, "p").unwrap(), "ABCDEF");
        assert_eq!(dkim_tag("v=DKIM1; k=rsa; p=", "p").unwrap(), "");
        assert_eq!(
            p_values(["v=DKIM1; p=", "v=DKIM1; p=AA", "p=AA"].iter().copied()),
            vec!["AA"]
        );
    }
}
