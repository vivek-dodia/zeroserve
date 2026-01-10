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

ZS_ENTRY
zs_u64 entry(void) {
  char method[16];
  char path[128];
  zs_s64 method_len = zs_req_method(method, sizeof(method));
  zs_s64 path_len = zs_req_path(path, sizeof(path));
  zs_u64 used_method_len = clamp_len(method_len, sizeof(method));
  zs_u64 used_path_len = clamp_len(path_len, sizeof(path));

  zs_log("method=", sizeof("method=") - 1);
  if (used_method_len > 0) {
    zs_log(method, used_method_len);
  }
  zs_log(" path=", sizeof(" path=") - 1);
  if (used_path_len > 0) {
    zs_log(path, used_path_len);
  }
  zs_log("\n", 1);

  return 0;
}
