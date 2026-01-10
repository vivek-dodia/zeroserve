#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    volatile int place = 0;
  char method[16];
  zs_s64 method_len = zs_req_method(method, sizeof(method));

  if (method_len == 3) {
      while(1) {
          place += 1;
      }
  }

  return 0;
}
