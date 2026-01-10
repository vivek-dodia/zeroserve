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

static int is_health_path(const char *path, zs_u64 len) {
  const char target[] = "/health";
  if (len != sizeof(target) - 1) {
    return 0;
  }
  for (zs_u64 i = 0; i < len; i++) {
    if (path[i] != target[i]) {
      return 0;
    }
  }
  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_s64 path_len = zs_req_path(path, sizeof(path));
  zs_u64 used_path_len = clamp_len(path_len, sizeof(path));

  if (used_path_len > 0 && is_health_path(path, used_path_len)) {
    const char body[] = "{\"ok\":true}\n";
    const char ctype[] = "application/json";
    zs_respond(
        200,
        body,
        sizeof(body) - 1,
        ctype,
        sizeof(ctype) - 1);
  }

  return 0;
}
