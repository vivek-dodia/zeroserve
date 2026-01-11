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

static int has_prefix(const char *value, zs_u64 len, const char *prefix, zs_u64 prefix_len) {
  if (len < prefix_len) {
    return 0;
  }
  for (zs_u64 i = 0; i < prefix_len; i++) {
    if (value[i] != prefix[i]) {
      return 0;
    }
  }
  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[128];
  zs_s64 path_len = zs_req_path(path, sizeof(path));
  zs_u64 used_path_len = clamp_len(path_len, sizeof(path));

  if (used_path_len > 0 && has_prefix(path, used_path_len, "/api", 4)) {
    const char backend[] = "http://127.0.0.1:9000";
    zs_reverse_proxy(backend, sizeof(backend) - 1);
  }

  return 0;
}
