use async_ebpf::program::HelperScope;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::json::JsonRef;
use crate::script::{deref_and_write_cstr, read_utf8, with_ectx};

/// Parameter struct for AWS V4 authorization header generation.
/// Must match the C definition in zeroserve.h exactly.
#[repr(C)]
pub struct AwsV4SignParams {
    // Credentials
    access_key_ptr: u64,
    access_key_len: u64,
    secret_key_ptr: u64,
    secret_key_len: u64,

    // Request metadata
    region_ptr: u64,
    region_len: u64,
    service_ptr: u64,
    service_len: u64,
    method_ptr: u64,
    method_len: u64,
    uri_ptr: u64,
    uri_len: u64,

    // Headers as JSON object handle
    headers_json: u64,

    // Body hash (hex-encoded SHA256 or "UNSIGNED-PAYLOAD")
    body_hash_ptr: u64,
    body_hash_len: u64,

    // Timestamp (Unix milliseconds)
    timestamp_ms: i64,

    // Output buffer
    out_ptr: u64,
    out_len: u64,
}

impl AwsV4SignParams {
    fn sanity_check(&self) -> bool {
        self.access_key_len <= 256
            && self.secret_key_len <= 256
            && self.region_len <= 64
            && self.service_len <= 64
            && self.method_len <= 64
            && self.uri_len <= 1024
    }
}

const SHORT_DATE: &str = "%Y%m%d";
const LONG_DATETIME: &str = "%Y%m%dT%H%M%SZ";

pub fn h_aws_v4_authorization_header(
    scope: &HelperScope,
    params_ptr: u64,
    params_len: u64,
    _: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // Validate struct alignment and size
    if params_ptr % std::mem::align_of::<AwsV4SignParams>() as u64 != 0 {
        return with_ectx(scope, |ctx| {
            ctx.error = "misaligned param ptr".into();
            Err(())
        });
    }
    if params_len != std::mem::size_of::<AwsV4SignParams>() as u64 {
        return with_ectx(scope, |ctx| {
            ctx.error = format!(
                "incorrect param size: expected {}, got {}",
                std::mem::size_of::<AwsV4SignParams>(),
                params_len
            );
            Err(())
        });
    }

    // Read params from script memory
    let params = scope.user_memory(params_ptr, params_len)?;
    let params = unsafe { &*(params.as_ptr() as *const AwsV4SignParams) };

    if !params.sanity_check() {
        return Ok(-1i64 as u64);
    }

    // Read credential fields
    let access_key = read_utf8(scope, params.access_key_ptr, params.access_key_len)?;
    let secret_key = read_utf8(scope, params.secret_key_ptr, params.secret_key_len)?;
    let region = read_utf8(scope, params.region_ptr, params.region_len)?;
    let service = read_utf8(scope, params.service_ptr, params.service_len)?;
    let method = read_utf8(scope, params.method_ptr, params.method_len)?;
    let uri = read_utf8(scope, params.uri_ptr, params.uri_len)?;
    let body_hash = read_utf8(scope, params.body_hash_ptr, params.body_hash_len)?;

    // Convert timestamp to DateTime<Utc>
    let timestamp_secs = params.timestamp_ms / 1000;
    let datetime: DateTime<Utc> = Utc.timestamp_opt(timestamp_secs, 0).single().ok_or(())?;

    // Parse URI to extract path and query
    let (path, query) = parse_uri(&uri);

    // Extract headers from JSON object
    let headers = with_ectx(scope, |ctx| {
        if params.headers_json == 0 {
            return Ok(Vec::new());
        }
        let json_ref = ctx.extobj::<JsonRef>(params.headers_json)?;
        let mut headers = Vec::new();

        json_ref
            .view(|value| {
                if let Some(obj) = value.as_object() {
                    for (key, value) in obj {
                        if let Some(val_str) = value.as_str() {
                            headers.push((key.to_lowercase(), val_str.to_string()));
                        }
                    }
                }
            })
            .map_err(|_| ())?;

        Ok(headers)
    })?;

    // Build authorization header
    let Ok(auth_header) = build_authorization_header(
        &access_key,
        &secret_key,
        &region,
        &service,
        &method,
        path,
        query,
        &headers,
        &body_hash,
        &datetime,
    ) else {
        return Ok(-2i64 as u64);
    };

    deref_and_write_cstr(scope, params.out_ptr, params.out_len, &auth_header)
}

pub fn h_aws_v4_presigned_url(
    scope: &HelperScope,
    params_ptr: u64,
    params_len: u64,
    expires_secs: u64,
    _: u64,
    _: u64,
) -> Result<u64, ()> {
    // Validate struct alignment and size
    if params_ptr % std::mem::align_of::<AwsV4SignParams>() as u64 != 0 {
        return with_ectx(scope, |ctx| {
            ctx.error = "misaligned param ptr".into();
            Err(())
        });
    }
    if params_len != std::mem::size_of::<AwsV4SignParams>() as u64 {
        return with_ectx(scope, |ctx| {
            ctx.error = format!(
                "incorrect param size: expected {}, got {}",
                std::mem::size_of::<AwsV4SignParams>(),
                params_len
            );
            Err(())
        });
    }

    // Read params from script memory
    let params = scope.user_memory(params_ptr, params_len)?;
    let params = unsafe { &*(params.as_ptr() as *const AwsV4SignParams) };

    if !params.sanity_check() {
        return Ok(-1i64 as u64);
    }

    // Read credential fields
    let access_key = read_utf8(scope, params.access_key_ptr, params.access_key_len)?;
    let secret_key = read_utf8(scope, params.secret_key_ptr, params.secret_key_len)?;
    let region = read_utf8(scope, params.region_ptr, params.region_len)?;
    let service = read_utf8(scope, params.service_ptr, params.service_len)?;
    let method = read_utf8(scope, params.method_ptr, params.method_len)?;
    let uri = read_utf8(scope, params.uri_ptr, params.uri_len)?;

    // Convert timestamp to DateTime<Utc>
    let timestamp_secs = params.timestamp_ms / 1000;
    let datetime: DateTime<Utc> = Utc.timestamp_opt(timestamp_secs, 0).single().ok_or(())?;

    // Parse URI to extract path and query
    let (path, existing_query) = parse_uri(&uri);

    // Extract headers from JSON object
    let headers = with_ectx(scope, |ctx| {
        if params.headers_json == 0 {
            return Ok(Vec::new());
        }
        let json_ref = ctx.extobj::<JsonRef>(params.headers_json)?;
        let mut headers = Vec::new();

        json_ref
            .view(|value| {
                if let Some(obj) = value.as_object() {
                    for (key, value) in obj {
                        if let Some(val_str) = value.as_str() {
                            headers.push((key.to_lowercase(), val_str.to_string()));
                        }
                    }
                }
            })
            .map_err(|_| ())?;

        Ok(headers)
    })?;

    // Build pre-signed URL
    let Ok(presigned_url) = build_presigned_url(
        &access_key,
        &secret_key,
        &region,
        &service,
        &method,
        path,
        existing_query,
        &headers,
        &datetime,
        expires_secs,
    ) else {
        return Ok(-2i64 as u64);
    };

    deref_and_write_cstr(scope, params.out_ptr, params.out_len, &presigned_url)
}

fn parse_uri<'a>(uri: &'a str) -> (&'a str, Option<&'a str>) {
    // Parse URI: /path?query or just /path
    if let Some(qmark_pos) = uri.find('?') {
        let path = &uri[..qmark_pos];
        let query = &uri[qmark_pos + 1..];
        (path, Some(query))
    } else {
        (uri, None)
    }
}

fn build_authorization_header(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    body_hash: &str,
    datetime: &DateTime<Utc>,
) -> Result<String, ()> {
    // Build canonical request
    let canonical_req = build_canonical_request(method, path, query, headers, body_hash)?;

    // Build string to sign
    let string_to_sign = build_string_to_sign(datetime, region, &canonical_req, service);

    // Calculate signature
    let signing_key = generate_signing_key(secret_key, datetime, region, service)?;
    let signature = calculate_signature(&signing_key, &string_to_sign);

    // Build signed headers string
    let signed_headers: Vec<String> = headers.iter().map(|(k, _)| k.clone()).collect();
    let signed_headers_str = signed_headers.join(";");

    // Build authorization header
    let scope = format!(
        "{}/{}/{}/aws4_request",
        datetime.format(SHORT_DATE),
        region,
        service
    );

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers_str, signature
    );

    // Note: Session token doesn't affect the Authorization header calculation in standard SigV4
    // It's passed as a separate x-amz-security-token header by the script

    Ok(auth)
}

fn build_presigned_url(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    method: &str,
    path: &str,
    existing_query: Option<&str>,
    headers: &[(String, String)],
    datetime: &DateTime<Utc>,
    expires_secs: u64,
) -> Result<String, ()> {
    let date = datetime.format(SHORT_DATE).to_string();
    let timestamp = datetime.format(LONG_DATETIME).to_string();
    let scope = format!("{}/{}/{}/aws4_request", date, region, service);

    // Build signed headers string (only host is typically required for presigned URLs)
    let signed_headers: Vec<String> = headers.iter().map(|(k, _)| k.clone()).collect();
    let signed_headers_str = if signed_headers.is_empty() {
        "host".to_string()
    } else {
        signed_headers.join(";")
    };

    // Build the query string with signing parameters
    let mut query_params: Vec<(String, String)> = Vec::new();

    // Add existing query params
    if let Some(q) = existing_query {
        for pair in q.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                query_params.push((pair[..eq_pos].to_string(), pair[eq_pos + 1..].to_string()));
            } else if !pair.is_empty() {
                query_params.push((pair.to_string(), String::new()));
            }
        }
    }

    // Add AWS signing parameters
    query_params.push((
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    ));
    query_params.push((
        "X-Amz-Credential".to_string(),
        format!("{}/{}", access_key, scope),
    ));
    query_params.push(("X-Amz-Date".to_string(), timestamp.clone()));
    query_params.push(("X-Amz-Expires".to_string(), expires_secs.to_string()));
    query_params.push((
        "X-Amz-SignedHeaders".to_string(),
        signed_headers_str.clone(),
    ));

    // Sort query params by key
    query_params.sort_by(|a, b| a.0.cmp(&b.0));

    // Build canonical query string
    let canonical_query = query_params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // Build canonical request
    let uri_encoded = uri_encode(path, false);

    // Canonical headers
    let mut header_lines: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_lowercase(), v.trim()))
        .collect();
    header_lines.sort();
    let canonical_headers = header_lines.join("\n");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n\n{}\nUNSIGNED-PAYLOAD",
        method.to_uppercase(),
        uri_encoded,
        canonical_query,
        canonical_headers,
        signed_headers_str
    );

    // Build string to sign
    let string_to_sign = build_string_to_sign(datetime, region, &canonical_request, service);

    // Calculate signature
    let signing_key = generate_signing_key(secret_key, datetime, region, service)?;
    let signature = calculate_signature(&signing_key, &string_to_sign);

    // Build final URL
    let final_query = query_params
        .into_iter()
        .map(|(k, v)| format!("{}={}", uri_encode(&k, true), uri_encode(&v, true)))
        .collect::<Vec<_>>()
        .join("&");

    Ok(format!(
        "{}?{}&X-Amz-Signature={}",
        path, final_query, signature
    ))
}

fn build_canonical_request(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    body_hash: &str,
) -> Result<String, ()> {
    // URI-encode path (except slashes)
    let uri_encoded = uri_encode(path, false);

    // Canonical query string
    let canonical_query = if let Some(q) = query {
        canonical_query_string(q)
    } else {
        String::new()
    };

    // Canonical headers
    let mut header_lines: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_lowercase(), v.trim()))
        .collect();
    header_lines.sort();
    let canonical_headers = header_lines.join("\n");

    // Signed headers
    let mut signed_headers: Vec<String> = headers.iter().map(|(k, _)| k.to_lowercase()).collect();
    signed_headers.sort();
    let signed_headers_str = signed_headers.join(";");

    Ok(format!(
        "{}\n{}\n{}\n{}\n\n{}\n{}",
        method.to_uppercase(),
        uri_encoded,
        canonical_query,
        canonical_headers,
        signed_headers_str,
        body_hash
    ))
}

fn canonical_query_string(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();

    for pair in query.split('&') {
        if let Some(eq_pos) = pair.find('=') {
            let key = uri_encode(&pair[..eq_pos], true);
            let value = uri_encode(&pair[eq_pos + 1..], true);
            pairs.push((key, value));
        } else if !pair.is_empty() {
            let key = uri_encode(pair, true);
            pairs.push((key, String::new()));
        }
    }

    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    pairs
        .into_iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(string: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(string.len() * 2);
    for c in string.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '~' | '.' | '%' => result.push(c),
            '/' if !encode_slash => result.push('/'),
            _ => {
                result.push('%');
                for b in c.to_string().bytes() {
                    result.push_str(&format!("{:02X}", b));
                }
            }
        }
    }
    result
}

fn build_string_to_sign(
    datetime: &DateTime<Utc>,
    region: &str,
    canonical_req: &str,
    service: &str,
) -> String {
    let hash = sha256_hex(canonical_req.as_bytes());
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/{}/aws4_request\n{}",
        datetime.format(LONG_DATETIME),
        datetime.format(SHORT_DATE),
        region,
        service,
        hash
    )
}

fn generate_signing_key(
    secret_key: &str,
    datetime: &DateTime<Utc>,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, ()> {
    type HmacSha256 = Hmac<Sha256>;

    let secret = format!("AWS4{}", secret_key);

    // kDate = HMAC("AWS4" + secret_key, date)
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ())?;
    mac.update(datetime.format(SHORT_DATE).to_string().as_bytes());
    let k_date = mac.finalize().into_bytes();

    // kRegion = HMAC(kDate, region)
    let mut mac = HmacSha256::new_from_slice(&k_date).map_err(|_| ())?;
    mac.update(region.as_bytes());
    let k_region = mac.finalize().into_bytes();

    // kService = HMAC(kRegion, service)
    let mut mac = HmacSha256::new_from_slice(&k_region).map_err(|_| ())?;
    mac.update(service.as_bytes());
    let k_service = mac.finalize().into_bytes();

    // kSigning = HMAC(kService, "aws4_request")
    let mut mac = HmacSha256::new_from_slice(&k_service).map_err(|_| ())?;
    mac.update(b"aws4_request");
    let k_signing = mac.finalize().into_bytes();

    Ok(k_signing.to_vec())
}

fn calculate_signature(signing_key: &[u8], string_to_sign: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC can take key of any size");
    mac.update(string_to_sign.as_bytes());
    let result = mac.finalize().into_bytes();
    hex_encode(&result)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_encode() {
        assert_eq!(uri_encode("/path/to/file", false), "/path/to/file");
        assert_eq!(uri_encode("/path/to file", false), "/path/to%20file");
        assert_eq!(uri_encode("/path/to/file", true), "%2Fpath%2Fto%2Ffile");
    }

    #[test]
    fn test_canonical_query_string() {
        assert_eq!(canonical_query_string("foo=bar&baz=qux"), "baz=qux&foo=bar");
        assert_eq!(canonical_query_string("a=1&a=2"), "a=1&a=2");
    }

    #[test]
    fn test_build_canonical_request() {
        let headers = vec![("host".to_string(), "example.com".to_string())];
        let req = build_canonical_request(
            "GET",
            "/",
            None,
            &headers,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();

        assert!(req.starts_with("GET\n/\n\nhost:example.com\n\nhost\n"));
    }
}
