#include <zeroserve.h>

static zs_u64 clamp_len(zs_s64 len, zs_u64 cap) {
  if (len <= 0 || cap == 0) {
    return 0;
  }
  if ((zs_u64)len >= cap) {
    return cap - 1;
  }
  return (zs_u64)len;
}

static zs_u64 u64_to_dec(char *out, zs_u64 out_len, zs_u64 value) {
  char tmp[32];
  zs_u64 i = 0;

  if (out_len == 0) {
    return 0;
  }

  if (value == 0) {
    out[0] = '0';
    if (out_len > 1) {
      out[1] = 0;
      return 1;
    }
    return 0;
  }

  while (value > 0 && i < sizeof(tmp)) {
    tmp[i++] = (char)('0' + (value % 10));
    value /= 10;
  }

  zs_u64 n = i;
  if (n >= out_len) {
    n = out_len - 1;
  }
  for (zs_u64 j = 0; j < n; j++) {
    out[j] = tmp[i - 1 - j];
  }
  out[n] = 0;
  return n;
}

ZS_ENTRY
zs_u64 entry(void) {
  char name[64];
  zs_s64 name_len = zs_req_query_param("name", sizeof("name") - 1, name, sizeof(name));
  zs_u64 used_name_len = clamp_len(name_len, sizeof(name));
  if (used_name_len == 0) {
    const char *fallback = "world";
    zs_meta_set("name", sizeof("name") - 1, fallback, sizeof("world") - 1);
  } else {
    zs_meta_set("name", sizeof("name") - 1, name, used_name_len);
  }

  char method[16];
  zs_s64 method_len = zs_req_method(method, sizeof(method));
  zs_u64 used_method_len = clamp_len(method_len, sizeof(method));
  if (used_method_len > 0) {
    zs_meta_set("method", sizeof("method") - 1, method, used_method_len);
  }

  char now_buf[32];
  zs_u64 now_len = u64_to_dec(now_buf, sizeof(now_buf), zs_now_ms());
  if (now_len > 0) {
    zs_meta_set("now_ms", sizeof("now_ms") - 1, now_buf, now_len);
  }

  return 0;
}
