//! Streaming response compression for the Caddy `encode` handler.
//!
//! This module mirrors the observable behavior of Caddy's
//! `modules/caddyhttp/encode` handler: `Accept-Encoding` negotiation, the
//! default response matcher (text-like content types), the `minimum_length`
//! gate, the set of headers it mutates, and streaming gzip/zstd encoders.
//!
//! It is deliberately self-contained and runtime-agnostic so it can be unit
//! tested in isolation and driven from any of the response-writing paths
//! (static, reverse_proxy, file_server) on either HTTP/1.1 or HTTP/2.

use std::collections::BTreeMap;
use std::io::Write;

use serde::Deserialize;

/// Caddy's default `minimum_length` (bytes) applied when unset or zero.
pub const DEFAULT_MIN_LENGTH: usize = 512;

/// Caddy's default gzip compression level (`defaultGzipLevel`).
const DEFAULT_GZIP_LEVEL: i32 = 5;

/// The default `prefer` order Caddy applies when none is configured, filtered
/// to the encoders zeroserve implements (no brotli).
const DEFAULT_PREFER: &[&str] = &["zstd", "gzip"];

/// Content-Type patterns Caddy compresses by default (the "common text-based
/// content types" list from the encode handler's Provision). Kept verbatim so
/// the default matcher behaves identically.
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/atom+xml*",
    "application/eot*",
    "application/font*",
    "application/geo+json*",
    "application/graphql+json*",
    "application/graphql-response+json*",
    "application/javascript*",
    "application/json*",
    "application/ld+json*",
    "application/manifest+json*",
    "application/opentype*",
    "application/otf*",
    "application/rss+xml*",
    "application/truetype*",
    "application/ttf*",
    "application/vnd.api+json*",
    "application/vnd.ms-fontobject*",
    "application/wasm*",
    "application/x-httpd-cgi*",
    "application/x-javascript*",
    "application/x-opentype*",
    "application/x-otf*",
    "application/x-perl*",
    "application/x-protobuf*",
    "application/x-ttf*",
    "application/xhtml+xml*",
    "application/xml*",
    "font/ttf*",
    "font/otf*",
    "image/svg+xml*",
    "image/vnd.microsoft.icon*",
    "image/x-icon*",
    "multipart/bag*",
    "multipart/mixed*",
    "text/*",
];

// === Configuration (deserialized from the Caddy `encode` handler JSON) ===

/// The raw `encode` handler config as emitted by the compiler / Caddy JSON.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EncodeConfigRaw {
    #[serde(default, rename = "minimum_length")]
    pub minimum_length: i64,
    #[serde(default)]
    pub prefer: Vec<String>,
    #[serde(default)]
    pub encodings: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "match")]
    pub matcher: Option<ResponseMatcherRaw>,
}

/// Caddy `ResponseMatcher`: status codes and header value patterns.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResponseMatcherRaw {
    #[serde(default)]
    pub status_code: Vec<i64>,
    #[serde(default)]
    pub headers: BTreeMap<String, Option<Vec<String>>>,
}

/// A resolved encoder choice with its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderSpec {
    Gzip { level: i32 },
    Zstd { level: i32, checksum: bool },
}

/// Resolved, ready-to-use encode configuration with Caddy defaults applied.
#[derive(Debug, Clone)]
pub struct EncodeConfig {
    pub min_length: usize,
    /// Encoder preference order (server preference for tie-breaking).
    pub prefer: Vec<String>,
    /// Available encoders by `Accept-Encoding` token (e.g. "gzip", "zstd").
    pub encoders: BTreeMap<String, EncoderSpec>,
    pub matcher: ResponseMatcher,
}

/// Resolved response matcher.
#[derive(Debug, Clone)]
pub struct ResponseMatcher {
    /// Configured status codes; empty means "any status".
    pub status_code: Vec<i64>,
    /// Header patterns; `None` value means "header must be absent", empty Vec
    /// means "header must be present", non-empty means "match a pattern".
    pub headers: BTreeMap<String, Option<Vec<String>>>,
}

impl EncodeConfig {
    /// Resolve a raw config (applying Caddy defaults) into a usable config.
    /// Returns `None` if no usable encoder is configured.
    pub fn resolve(raw: &EncodeConfigRaw) -> Option<EncodeConfig> {
        let mut encoders = BTreeMap::new();
        for (name, value) in &raw.encodings {
            if let Some(spec) = resolve_encoder(name, value) {
                encoders.insert(name.clone(), spec);
            }
        }
        if encoders.is_empty() {
            return None;
        }

        // Prefer order: configured order filtered to available encoders, else
        // Caddy's default order ([zstd, br, gzip] minus unsupported br).
        let mut prefer: Vec<String> = raw
            .prefer
            .iter()
            .filter(|name| encoders.contains_key(*name))
            .cloned()
            .collect();
        if prefer.is_empty() {
            for name in DEFAULT_PREFER {
                if encoders.contains_key(*name) {
                    prefer.push((*name).to_string());
                }
            }
        }

        let min_length = if raw.minimum_length <= 0 {
            DEFAULT_MIN_LENGTH
        } else {
            raw.minimum_length as usize
        };

        let matcher = match &raw.matcher {
            Some(m) => ResponseMatcher {
                status_code: m.status_code.clone(),
                headers: m.headers.clone(),
            },
            None => ResponseMatcher::default_text(),
        };

        Some(EncodeConfig {
            min_length,
            prefer,
            encoders,
            matcher,
        })
    }
}

impl ResponseMatcher {
    /// The default text-content-type matcher Caddy installs when none is set.
    fn default_text() -> ResponseMatcher {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            Some(
                DEFAULT_CONTENT_TYPES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
        );
        ResponseMatcher {
            status_code: Vec::new(),
            headers,
        }
    }

    /// Mirror of Caddy `ResponseMatcher.Match`: status code then header values.
    pub fn matches(&self, status: u16, header_lookup: impl Fn(&str) -> Vec<String>) -> bool {
        if !self.match_status(status) {
            return false;
        }
        for (field, allowed) in &self.headers {
            let actual = header_lookup(field);
            match allowed {
                // Non-nil but empty: match if the header exists at all.
                Some(patterns) if patterns.is_empty() => {
                    if actual.is_empty() {
                        return false;
                    }
                }
                // Nil: match if the header does NOT exist.
                None => {
                    if !actual.is_empty() {
                        return false;
                    }
                }
                Some(patterns) => {
                    let mut matched = false;
                    'vals: for value in &actual {
                        for pattern in patterns {
                            if header_value_matches(value, pattern) {
                                matched = true;
                                break 'vals;
                            }
                        }
                    }
                    if !matched {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn match_status(&self, status: u16) -> bool {
        if self.status_code.is_empty() {
            return true;
        }
        self.status_code
            .iter()
            .any(|code| status_code_matches(status as i64, *code))
    }
}

/// Mirror of Caddy `StatusCodeMatches`: exact, or a `2`/`3`-style class.
fn status_code_matches(actual: i64, configured: i64) -> bool {
    if actual == configured {
        return true;
    }
    configured < 100 && actual >= configured * 100 && actual < (configured + 1) * 100
}

/// Mirror of Caddy `matchHeaders` per-value wildcard logic.
fn header_value_matches(actual: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let starts = pattern.starts_with('*');
    let ends = pattern.ends_with('*');
    if starts && ends {
        let inner = &pattern[1..pattern.len() - 1];
        actual.contains(inner)
    } else if starts {
        actual.ends_with(&pattern[1..])
    } else if ends {
        actual.starts_with(&pattern[..pattern.len() - 1])
    } else {
        actual == pattern
    }
}

fn resolve_encoder(name: &str, value: &serde_json::Value) -> Option<EncoderSpec> {
    match name {
        "gzip" => {
            let level = value
                .get("level")
                .and_then(serde_json::Value::as_i64)
                .map(|l| l as i32)
                .filter(|l| *l != 0)
                .unwrap_or(DEFAULT_GZIP_LEVEL);
            Some(EncoderSpec::Gzip { level })
        }
        "zstd" => {
            let level = value
                .get("level")
                .and_then(serde_json::Value::as_str)
                .map(zstd_level)
                .unwrap_or(ZSTD_DEFAULT_LEVEL);
            let checksum = value
                .get("checksum")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Some(EncoderSpec::Zstd { level, checksum })
        }
        _ => None,
    }
}

// klauspost/compress zstd speed names mapped onto libzstd levels.
const ZSTD_DEFAULT_LEVEL: i32 = 3;

fn zstd_level(name: &str) -> i32 {
    match name {
        "fastest" => 1,
        "better" => 7,
        "best" => 11,
        _ => ZSTD_DEFAULT_LEVEL, // "default" and anything else
    }
}

// === Accept-Encoding negotiation (mirror of Caddy AcceptedEncodings) ===

struct EncodingPreference {
    encoding: String,
    q: f64,
    prefer_order: i64,
}

/// Mirror of Caddy `AcceptedEncodings`: returns the client's accepted encodings
/// ordered by descending q-factor then descending server preference.
pub fn accepted_encodings(
    accept_encoding: &str,
    sec_websocket_key: &str,
    prefer: &[String],
) -> Vec<String> {
    if accept_encoding.is_empty() {
        return Vec::new();
    }
    let mut prefs: Vec<EncodingPreference> = Vec::new();
    for accepted in accept_encoding.split(',') {
        let mut parts = accepted.split(';');
        let enc_name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if enc_name.is_empty() {
            continue;
        }
        let mut q_factor = 1.0_f64;
        if let Some(q_str) = parts.next() {
            let q_str = q_str.trim().to_ascii_lowercase();
            if let Some(rest) = q_str.strip_prefix("q=")
                && let Ok(parsed) = rest.parse::<f32>()
            {
                let parsed = parsed as f64;
                if (0.0..=1.0).contains(&parsed) {
                    q_factor = parsed;
                }
            }
        }
        // q=0 means not accepted.
        if q_factor < 0.00001 {
            continue;
        }
        // Don't encode WebSocket handshakes (except identity).
        if !sec_websocket_key.is_empty() && enc_name != "identity" {
            continue;
        }
        let mut prefer_order: i64 = prefer
            .iter()
            .position(|p| p == &enc_name)
            .map_or(-1, |i| i as i64);
        if prefer_order > -1 {
            prefer_order = prefer.len() as i64 - prefer_order;
        }
        prefs.push(EncodingPreference {
            encoding: enc_name,
            q: q_factor,
            prefer_order,
        });
    }
    // Stable sort: descending q, then descending prefer_order.
    prefs.sort_by(|a, b| {
        if (a.q - b.q).abs() < 0.00001 {
            b.prefer_order.cmp(&a.prefer_order)
        } else {
            b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal)
        }
    });
    prefs.into_iter().map(|p| p.encoding).collect()
}

impl EncodeConfig {
    /// Pick the encoder to use for this request, or `None` if the client does
    /// not accept any configured encoding.
    pub fn negotiate(
        &self,
        accept_encoding: &str,
        sec_websocket_key: &str,
    ) -> Option<(String, EncoderSpec)> {
        for name in accepted_encodings(accept_encoding, sec_websocket_key, &self.prefer) {
            if let Some(spec) = self.encoders.get(&name) {
                return Some((name, *spec));
            }
        }
        None
    }
}

/// Whether `Cache-Control` permits transformation (no `no-transform`).
pub fn encode_allowed(cache_control: Option<&str>) -> bool {
    !cache_control.unwrap_or("").contains("no-transform")
}

// === Per-request decision and header mutation ===

/// Per-request compression state: the resolved config plus the request headers
/// that drive negotiation. Built once when a response is about to be written.
#[derive(Debug, Clone)]
pub struct EncodeState {
    pub config: EncodeConfig,
    pub accept_encoding: String,
    pub sec_websocket_key: String,
}

/// The encoding chosen for a particular response.
#[derive(Debug, Clone)]
pub struct ChosenEncoding {
    pub name: String,
    pub spec: EncoderSpec,
}

impl EncodeState {
    /// Build per-request encode state from a resolved config and the request's
    /// `Accept-Encoding` / `Sec-WebSocket-Key` headers.
    pub fn new(
        config: EncodeConfig,
        accept_encoding: &str,
        sec_websocket_key: &str,
    ) -> EncodeState {
        EncodeState {
            config,
            accept_encoding: accept_encoding.to_string(),
            sec_websocket_key: sec_websocket_key.to_string(),
        }
    }

    /// Build from an `http::HeaderMap` of request headers.
    pub fn from_request_headers(config: EncodeConfig, headers: &::http::HeaderMap) -> EncodeState {
        let get = |name: ::http::header::HeaderName| -> &str {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        };
        EncodeState::new(
            config,
            get(::http::header::ACCEPT_ENCODING),
            get(::http::header::SEC_WEBSOCKET_KEY),
        )
    }

    /// Decide whether to compress this response and with which encoding.
    ///
    /// `content_length` is the known body length when available; `None` means
    /// the length is not yet known (streamed) and the `minimum_length` gate must
    /// be applied at the body level instead.
    pub fn decide(
        &self,
        status: u16,
        headers: &::http::HeaderMap,
        content_length: Option<u64>,
    ) -> Option<ChosenEncoding> {
        // Already encoded by an upstream/handler: never double-encode.
        if let Some(ce) = headers.get(::http::header::CONTENT_ENCODING)
            && !ce.is_empty()
        {
            return None;
        }
        let cache_control = headers
            .get(::http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok());
        if !encode_allowed(cache_control) {
            return None;
        }
        if !self.config.matcher.matches(status, |field| {
            headers
                .get_all(field)
                .iter()
                .filter_map(|v| v.to_str().ok().map(str::to_string))
                .collect()
        }) {
            return None;
        }
        let (name, spec) = self
            .config
            .negotiate(&self.accept_encoding, &self.sec_websocket_key)?;
        if let Some(len) = content_length
            && (len as usize) <= self.config.min_length
        {
            return None;
        }
        Some(ChosenEncoding { name, spec })
    }

    pub fn min_length(&self) -> usize {
        self.config.min_length
    }
}

/// Whether the response's existing `Vary` header already lists `Accept-Encoding`.
fn vary_has_accept_encoding(headers: &::http::HeaderMap) -> bool {
    headers.get_all(::http::header::VARY).iter().any(|v| {
        v.to_str()
            .ok()
            .map(|s| {
                s.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("accept-encoding"))
            })
            .unwrap_or(false)
    })
}

/// Apply the header changes Caddy makes when it commits to compressing with
/// `encoding`: drop `Content-Length`, set `Content-Encoding`, add
/// `Vary: Accept-Encoding`, drop `Accept-Ranges`, and suffix a strong `ETag`.
pub fn apply_encoding_headers(headers: &mut ::http::HeaderMap, encoding: &str) {
    use ::http::header::{
        ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, ETAG, HeaderValue, VARY,
    };
    headers.remove(CONTENT_LENGTH);
    if let Ok(value) = HeaderValue::from_str(encoding) {
        headers.insert(CONTENT_ENCODING, value);
    }
    if !vary_has_accept_encoding(headers) {
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    headers.remove(ACCEPT_RANGES);
    if let Some(etag) = headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        && !etag.starts_with("W/")
    {
        let trimmed = etag.strip_suffix('"').unwrap_or(&etag);
        if let Ok(value) = HeaderValue::from_str(&format!("{trimmed}-{encoding}\"")) {
            headers.insert(ETAG, value);
        }
    }
}

// === Streaming encoders ===

/// A streaming compressor that produces output incrementally.
pub enum BodyEncoder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl BodyEncoder {
    pub fn new(spec: EncoderSpec) -> std::io::Result<BodyEncoder> {
        match spec {
            EncoderSpec::Gzip { level } => {
                // miniz_oxide supports levels 0..=9; clamp Caddy's wider range.
                let level = level.clamp(0, 9) as u32;
                Ok(BodyEncoder::Gzip(flate2::write::GzEncoder::new(
                    Vec::new(),
                    flate2::Compression::new(level),
                )))
            }
            EncoderSpec::Zstd { level, checksum } => {
                let mut enc = zstd::stream::write::Encoder::new(Vec::new(), level)?;
                enc.include_checksum(checksum)?;
                Ok(BodyEncoder::Zstd(enc))
            }
        }
    }

    /// Feed `data` into the encoder and return any compressed bytes produced so
    /// far (draining the internal output buffer).
    pub fn push(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            BodyEncoder::Gzip(e) => {
                e.write_all(data)?;
                Ok(std::mem::take(e.get_mut()))
            }
            BodyEncoder::Zstd(e) => {
                e.write_all(data)?;
                Ok(std::mem::take(e.get_mut()))
            }
        }
    }

    /// Compress a fully-buffered body in one shot, returning the compressed
    /// bytes (used for buffered responses where the length is known up front).
    pub fn compress_buffer(spec: EncoderSpec, body: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut enc = BodyEncoder::new(spec)?;
        let mut out = enc.push(body)?;
        out.extend(enc.finish()?);
        Ok(out)
    }

    /// Finish the stream, returning the final trailing bytes.
    pub fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            BodyEncoder::Gzip(e) => e.finish(),
            BodyEncoder::Zstd(e) => e.finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn cfg(json: &str) -> EncodeConfig {
        let raw: EncodeConfigRaw = serde_json::from_str(json).unwrap();
        EncodeConfig::resolve(&raw).unwrap()
    }

    #[test]
    fn resolve_applies_defaults() {
        let c = cfg(r#"{"encodings": {"gzip": {}}}"#);
        assert_eq!(c.min_length, DEFAULT_MIN_LENGTH);
        assert_eq!(c.prefer, vec!["gzip".to_string()]);
        assert!(matches!(c.encoders["gzip"], EncoderSpec::Gzip { level: 5 }));
    }

    #[test]
    fn resolve_default_prefer_order_zstd_then_gzip() {
        let c = cfg(r#"{"encodings": {"gzip": {}, "zstd": {}}}"#);
        assert_eq!(c.prefer, vec!["zstd".to_string(), "gzip".to_string()]);
    }

    #[test]
    fn resolve_respects_configured_prefer() {
        let c = cfg(r#"{"encodings": {"gzip": {}, "zstd": {}}, "prefer": ["gzip", "zstd"]}"#);
        assert_eq!(c.prefer, vec!["gzip".to_string(), "zstd".to_string()]);
    }

    #[test]
    fn resolve_minimum_length_zero_is_default() {
        let c = cfg(r#"{"encodings": {"gzip": {}}, "minimum_length": 0}"#);
        assert_eq!(c.min_length, DEFAULT_MIN_LENGTH);
        let c = cfg(r#"{"encodings": {"gzip": {}}, "minimum_length": 256}"#);
        assert_eq!(c.min_length, 256);
    }

    #[test]
    fn zstd_levels_and_checksum() {
        let c = cfg(r#"{"encodings": {"zstd": {"level": "best", "checksum": true}}}"#);
        assert_eq!(
            c.encoders["zstd"],
            EncoderSpec::Zstd {
                level: 11,
                checksum: true
            }
        );
        let c = cfg(r#"{"encodings": {"zstd": {}}}"#);
        assert_eq!(
            c.encoders["zstd"],
            EncoderSpec::Zstd {
                level: 3,
                checksum: false
            }
        );
    }

    #[test]
    fn negotiation_basic_and_qvalues() {
        // q-factor descending.
        assert_eq!(
            accepted_encodings("gzip;q=0.5, zstd;q=0.9", "", &[]),
            vec!["zstd".to_string(), "gzip".to_string()]
        );
        // q=0 excluded.
        assert_eq!(
            accepted_encodings("gzip;q=0, zstd", "", &[]),
            vec!["zstd".to_string()]
        );
        // empty header -> nothing.
        assert!(accepted_encodings("", "", &[]).is_empty());
    }

    #[test]
    fn negotiation_prefer_breaks_ties() {
        // Equal q: server prefer order wins (zstd before gzip).
        let prefer = vec!["zstd".to_string(), "gzip".to_string()];
        assert_eq!(
            accepted_encodings("gzip, zstd", "", &prefer),
            vec!["zstd".to_string(), "gzip".to_string()]
        );
    }

    #[test]
    fn negotiation_websocket_only_identity() {
        assert_eq!(
            accepted_encodings("gzip, identity", "dGhlIHNhbXBsZQ==", &[]),
            vec!["identity".to_string()]
        );
    }

    #[test]
    fn config_negotiate_picks_available() {
        let c = cfg(r#"{"encodings": {"gzip": {}}, "prefer": ["gzip"]}"#);
        // Client prefers zstd (not available) then gzip.
        let chosen = c.negotiate("zstd, gzip", "");
        assert_eq!(chosen.unwrap().0, "gzip");
        // Client only accepts br -> none.
        assert!(c.negotiate("br", "").is_none());
    }

    #[test]
    fn default_matcher_matches_text_not_binary() {
        let c = cfg(r#"{"encodings": {"gzip": {}}}"#);
        let m = &c.matcher;
        assert!(m.matches(200, |f| if f == "Content-Type" {
            vec!["text/html; charset=utf-8".into()]
        } else {
            vec![]
        }));
        assert!(m.matches(200, |f| if f == "Content-Type" {
            vec!["application/json".into()]
        } else {
            vec![]
        }));
        assert!(!m.matches(200, |f| if f == "Content-Type" {
            vec!["image/png".into()]
        } else {
            vec![]
        }));
    }

    #[test]
    fn custom_status_matcher() {
        let raw: EncodeConfigRaw =
            serde_json::from_str(r#"{"encodings": {"gzip": {}}, "match": {"status_code": [2]}}"#)
                .unwrap();
        let c = EncodeConfig::resolve(&raw).unwrap();
        // No header constraint -> any content type; status class 2xx.
        assert!(c.matcher.matches(204, |_| vec![]));
        assert!(!c.matcher.matches(404, |_| vec![]));
    }

    #[test]
    fn header_wildcards() {
        assert!(header_value_matches("text/html", "text/*"));
        assert!(header_value_matches("application/json", "*json*"));
        assert!(header_value_matches("application/xml", "*xml"));
        assert!(!header_value_matches("image/png", "text/*"));
        assert!(header_value_matches("anything", "*"));
    }

    #[test]
    fn encode_allowed_no_transform() {
        assert!(encode_allowed(None));
        assert!(encode_allowed(Some("public, max-age=60")));
        assert!(!encode_allowed(Some("no-transform")));
        assert!(!encode_allowed(Some("public, no-transform")));
    }

    #[test]
    fn gzip_roundtrip_streaming() {
        let mut enc = BodyEncoder::new(EncoderSpec::Gzip { level: 5 }).unwrap();
        let mut out = Vec::new();
        out.extend(enc.push(b"hello ").unwrap());
        out.extend(enc.push(b"compressed ").unwrap());
        out.extend(enc.push(b"world").unwrap());
        out.extend(enc.finish().unwrap());

        let mut d = flate2::read::GzDecoder::new(&out[..]);
        let mut decoded = String::new();
        d.read_to_string(&mut decoded).unwrap();
        assert_eq!(decoded, "hello compressed world");
    }

    fn hmap(pairs: &[(&str, &str)]) -> ::http::HeaderMap {
        let mut h = ::http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                ::http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                ::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn state(json: &str, accept: &str) -> EncodeState {
        EncodeState::new(cfg(json), accept, "")
    }

    #[test]
    fn decide_compresses_text_when_accepted() {
        let s = state(r#"{"encodings": {"gzip": {}}}"#, "gzip");
        let resp = hmap(&[("Content-Type", "text/html; charset=utf-8")]);
        let chosen = s.decide(200, &resp, Some(1024)).unwrap();
        assert_eq!(chosen.name, "gzip");
    }

    #[test]
    fn decide_skips_when_below_min_length() {
        let s = state(r#"{"encodings": {"gzip": {}}}"#, "gzip");
        let resp = hmap(&[("Content-Type", "text/html")]);
        assert!(s.decide(200, &resp, Some(100)).is_none());
        // Unknown length defers (returns Some, body-level gate applies later).
        assert!(s.decide(200, &resp, None).is_some());
    }

    #[test]
    fn decide_skips_already_encoded_and_no_transform_and_binary() {
        let s = state(r#"{"encodings": {"gzip": {}}}"#, "gzip");
        assert!(
            s.decide(
                200,
                &hmap(&[("Content-Type", "text/html"), ("Content-Encoding", "gzip")]),
                Some(9999)
            )
            .is_none()
        );
        assert!(
            s.decide(
                200,
                &hmap(&[
                    ("Content-Type", "text/html"),
                    ("Cache-Control", "no-transform")
                ]),
                Some(9999)
            )
            .is_none()
        );
        assert!(
            s.decide(200, &hmap(&[("Content-Type", "image/png")]), Some(9999))
                .is_none()
        );
    }

    #[test]
    fn decide_skips_when_client_rejects() {
        let s = state(r#"{"encodings": {"gzip": {}}}"#, "br");
        assert!(
            s.decide(200, &hmap(&[("Content-Type", "text/html")]), Some(9999))
                .is_none()
        );
    }

    #[test]
    fn apply_headers_sets_encoding_and_vary_and_etag() {
        let mut h = hmap(&[
            ("Content-Length", "1234"),
            ("Accept-Ranges", "bytes"),
            ("Etag", "\"abc\""),
        ]);
        apply_encoding_headers(&mut h, "gzip");
        assert!(h.get(::http::header::CONTENT_LENGTH).is_none());
        assert!(h.get(::http::header::ACCEPT_RANGES).is_none());
        assert_eq!(h.get(::http::header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(h.get(::http::header::VARY).unwrap(), "Accept-Encoding");
        assert_eq!(h.get(::http::header::ETAG).unwrap(), "\"abc-gzip\"");
    }

    #[test]
    fn apply_headers_preserves_weak_etag_and_dedup_vary() {
        let mut h = hmap(&[("Etag", "W/\"abc\""), ("Vary", "Accept-Encoding")]);
        apply_encoding_headers(&mut h, "zstd");
        assert_eq!(h.get(::http::header::ETAG).unwrap(), "W/\"abc\"");
        // Vary not duplicated.
        assert_eq!(h.get_all(::http::header::VARY).iter().count(), 1);
    }

    #[test]
    fn buffered_response_recipe_matches_send_path() {
        // Mirrors what send_script_response does for a buffered body: decide,
        // compress_buffer, apply_encoding_headers, then set Content-Length.
        let s = state(
            r#"{"encodings": {"gzip": {}, "zstd": {}}, "prefer": ["zstd", "gzip"]}"#,
            "gzip",
        );
        let body = b"<html><body>".repeat(100); // > 512 bytes, text-like
        let mut headers = hmap(&[("Content-Type", "text/html"), ("Content-Length", "1200")]);
        let chosen = s.decide(200, &headers, Some(body.len() as u64)).unwrap();
        // Client only offered gzip, so gzip is chosen despite zstd preference.
        assert_eq!(chosen.name, "gzip");

        let compressed = BodyEncoder::compress_buffer(chosen.spec, &body).unwrap();
        apply_encoding_headers(&mut headers, &chosen.name);
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_str(&compressed.len().to_string()).unwrap(),
        );

        assert_eq!(
            headers.get(::http::header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert_eq!(
            headers.get(::http::header::VARY).unwrap(),
            "Accept-Encoding"
        );
        assert_eq!(
            headers.get(::http::header::CONTENT_LENGTH).unwrap(),
            compressed.len().to_string().as_str()
        );
        assert!(compressed.len() < body.len());

        let mut d = flate2::read::GzDecoder::new(&compressed[..]);
        let mut decoded = Vec::new();
        d.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn zstd_roundtrip_streaming() {
        let mut enc = BodyEncoder::new(EncoderSpec::Zstd {
            level: 3,
            checksum: true,
        })
        .unwrap();
        let mut out = Vec::new();
        for _ in 0..100 {
            out.extend(enc.push(b"the quick brown fox ").unwrap());
        }
        out.extend(enc.finish().unwrap());

        let decoded = zstd::stream::decode_all(&out[..]).unwrap();
        assert_eq!(decoded, b"the quick brown fox ".repeat(100));
    }
}
