#include <zeroserve.h>

static ZS_INLINE zs_u64 clamp_len(zs_s64 len, zs_u64 cap) {
  if (len <= 0 || cap == 0) {
    return 0;
  }
  if ((zs_u64)len >= cap) {
    return cap - 1;
  }
  return (zs_u64)len;
}

static ZS_INLINE void read_config_string(zs_u64 input, const char *key,
                                         zs_u64 key_len, char *out,
                                         zs_u64 out_len) {
  out[0] = '\0';
  zs_s64 config = zs_json_get(input, ZS_STR("config"));
  if (config < 0) {
    return;
  }

  zs_s64 node = zs_json_get(config, key, key_len);
  if (node >= 0) {
    zs_json_read_string(node, out, out_len);
    zs_object_free(node);
  }
  zs_object_free(config);
}

static ZS_INLINE void set_json_string(zs_u64 obj, const char *key,
                                      zs_u64 key_len, const char *value,
                                      zs_u64 value_len) {
  zs_s64 node = zs_json_new_object();
  if (node < 0) {
    return;
  }
  zs_json_set_string(node, value, value_len);
  zs_json_set(obj, key, key_len, node);
  zs_object_free(node);
}

static ZS_INLINE void set_action(zs_u64 out, const char *name,
                                 zs_u64 name_len) {
  set_json_string(out, ZS_STR("action"), name, name_len);
}

static ZS_INLINE zs_s64 result_continue(void) {
  zs_s64 out = zs_json_new_object();
  if (out >= 0) {
    set_action(out, ZS_STR("continue"));
  }
  return out;
}

static ZS_INLINE zs_s64 result_error(const char *message, zs_u64 message_len) {
  zs_s64 out = zs_json_new_object();
  if (out < 0) {
    return -1;
  }

  set_action(out, ZS_STR("error"));

  zs_s64 status = zs_json_new_object();
  if (status >= 0) {
    zs_json_set_i64(status, 500);
    zs_json_set(out, ZS_STR("status"), status);
    zs_object_free(status);
  }

  set_json_string(out, ZS_STR("message"), message, message_len);
  return out;
}

static ZS_INLINE void write_2(char *out, zs_u64 value) {
  out[0] = (char)('0' + ((value / 10) % 10));
  out[1] = (char)('0' + (value % 10));
}

static ZS_INLINE void write_4(char *out, zs_u64 value) {
  out[0] = (char)('0' + ((value / 1000) % 10));
  out[1] = (char)('0' + ((value / 100) % 10));
  out[2] = (char)('0' + ((value / 10) % 10));
  out[3] = (char)('0' + (value % 10));
}

static ZS_INLINE void aws_date(zs_u64 timestamp_ms, char out[17]) {
  zs_u64 seconds = timestamp_ms / 1000;
  zs_u64 z = (seconds / 86400) + 719468;
  zs_u64 sod = seconds % 86400;
  zs_u64 hour = sod / 3600;
  zs_u64 minute = (sod / 60) % 60;
  zs_u64 second = sod % 60;

  zs_u64 era = z / 146097;
  zs_u64 doe = z - era * 146097;
  zs_u64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  zs_u64 year = yoe + era * 400;
  zs_u64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  zs_u64 mp = (5 * doy + 2) / 153;
  zs_u64 day = doy - (153 * mp + 2) / 5 + 1;
  zs_u64 month = mp < 10 ? mp + 3 : mp - 9;
  if (month <= 2) {
    year += 1;
  }

  write_4(out, year);
  write_2(out + 4, month);
  write_2(out + 6, day);
  out[8] = 'T';
  write_2(out + 9, hour);
  write_2(out + 11, minute);
  write_2(out + 13, second);
  out[15] = 'Z';
  out[16] = '\0';
}

ZS_CALL_ENTRY(sign_request, input) {
  char access_key[256];
  char secret_key[256];
  char region[64];
  char service[32];
  char host[256];
  char body_hash[80];
  char session_token[256];

  read_config_string(input, ZS_STR("access_key_id"), access_key,
                     sizeof(access_key));
  read_config_string(input, ZS_STR("secret_access_key"), secret_key,
                     sizeof(secret_key));
  read_config_string(input, ZS_STR("region"), region, sizeof(region));
  read_config_string(input, ZS_STR("service"), service, sizeof(service));
  read_config_string(input, ZS_STR("host"), host, sizeof(host));
  if (host[0] == '\0') {
    read_config_string(input, ZS_STR("upstream_host"), host, sizeof(host));
  }
  read_config_string(input, ZS_STR("body_hash"), body_hash, sizeof(body_hash));
  read_config_string(input, ZS_STR("payload_hash"), body_hash,
                     sizeof(body_hash));
  read_config_string(input, ZS_STR("session_token"), session_token,
                     sizeof(session_token));

  if (access_key[0] == '\0' || secret_key[0] == '\0') {
    return result_error(ZS_STR("aws-sigv4 requires access_key_id and "
                               "secret_access_key"));
  }
  if (region[0] == '\0') {
    zs_strcpy(region, "us-east-1");
  }
  if (service[0] == '\0') {
    zs_strcpy(service, "s3");
  }
  if (host[0] == '\0') {
    zs_strcpy(host, "127.0.0.1:9000");
  }
  if (body_hash[0] == '\0') {
    zs_strcpy(body_hash, "UNSIGNED-PAYLOAD");
  }

  char method[16];
  zs_s64 method_raw = zs_req_method(method, sizeof(method));
  zs_u64 method_len = clamp_len(method_raw, sizeof(method));
  if (method_len == 0 || method_raw >= (zs_s64)sizeof(method)) {
    return result_error(ZS_STR("aws-sigv4 could not read request method"));
  }

  char uri[1024];
  zs_s64 uri_raw = zs_req_uri(uri, sizeof(uri));
  zs_u64 uri_len = clamp_len(uri_raw, sizeof(uri));
  if (uri_len == 0 || uri_raw >= (zs_s64)sizeof(uri)) {
    return result_error(ZS_STR("aws-sigv4 could not read request URI"));
  }

  zs_u64 now = zs_now_ms();
  char amz_date[17];
  aws_date(now, amz_date);

  zs_s64 headers = zs_json_new_object();
  if (headers < 0) {
    return result_error(ZS_STR("aws-sigv4 could not allocate headers"));
  }

  set_json_string(headers, ZS_STR("host"), ZS_STR(host));
  set_json_string(headers, ZS_STR("x-amz-content-sha256"), ZS_STR(body_hash));
  set_json_string(headers, ZS_STR("x-amz-date"), ZS_STR(amz_date));
  if (session_token[0] != '\0') {
    set_json_string(headers, ZS_STR("x-amz-security-token"),
                    ZS_STR(session_token));
  }

  char auth[1024];
  zs_aws_v4_sign_params params = {
      .access_key = access_key,
      .access_key_len = zs_strlen(access_key),
      .secret_key = secret_key,
      .secret_key_len = zs_strlen(secret_key),
      .region = region,
      .region_len = zs_strlen(region),
      .service = service,
      .service_len = zs_strlen(service),
      .method = method,
      .method_len = method_len,
      .uri = uri,
      .uri_len = uri_len,
      .headers_json = headers,
      .body_hash = body_hash,
      .body_hash_len = zs_strlen(body_hash),
      .timestamp_ms = (zs_s64)now,
      .out = auth,
      .out_len = sizeof(auth),
  };

  zs_s64 auth_len = zs_aws_v4_authorization_header(&params, sizeof(params));
  zs_object_free(headers);
  if (auth_len <= 0 || auth_len >= (zs_s64)sizeof(auth)) {
    return result_error(ZS_STR("aws-sigv4 signing failed"));
  }

  zs_req_set_header(ZS_STR("Host"), ZS_STR(host));
  zs_req_set_header(ZS_STR("X-Amz-Date"), ZS_STR(amz_date));
  zs_req_set_header(ZS_STR("X-Amz-Content-Sha256"), ZS_STR(body_hash));
  if (session_token[0] != '\0') {
    zs_req_set_header(ZS_STR("X-Amz-Security-Token"), ZS_STR(session_token));
  }
  zs_req_set_header(ZS_STR("Authorization"), auth, (zs_u64)auth_len);

  return result_continue();
}
