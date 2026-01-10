/*
 * Zeroserve script engine overview
 *
 * Scripts are eBPF programs compiled into BPF object files (.o) that live
 * inside the site tarball under .zeroserve/scripts. On reload, zeroserve
 * scans the tarball for that prefix, loads each .o, sorts them by path, and
 * executes them for every request.
 *
 * Entrypoint and flow:
 * - Each script must export a function in section "zeroserve.request".
 *   Use the ZS_ENTRY macro below to mark the entrypoint.
 * - Scripts run in sorted order for every request.
 * - A per-request metadata map is shared across scripts in the chain.
 * - If a script calls zs_respond, its response is used and later scripts
 *   are skipped.
 * - Script failures are logged and do not abort the chain.
 *
 * Data access:
 * - Request data is read via zs_req_* helpers (method, path, uri, query,
 *   scheme, peer, headers, query params).
 * - Header names are matched case-insensitively (stored lowercase internally).
 * - zs_meta_get/zs_meta_set expose a per-request string map shared by scripts.
 *
 * Helper I/O:
 * - String helpers write a C string into the provided buffer.
 * - Passing out_len=0 returns the required length for the value.
 * - zs_log writes to the server log, buffering until a newline or ~512 bytes.
 * - zs_date / zs_now_ms return milliseconds since the Unix epoch.
 *
 * Building:
 * - Compile C sources to BPF with:
 *     clang -O2 -target bpf -emit-llvm -c input.c -o tmp.bc
 *     llc -march=bpf -bpf-stack-size=4096 -mcpu=v3 -filetype=obj tmp.bc -o out.o
 * - #include <zeroserve.h> to pull in this header.
 * - `zeroserve --pack` provides the header automatically; use
 *   `zeroserve --dump-sdk` to print it to stdout.
 *
 * Packaging:
 * - With `zeroserve --pack`, any `.c` files in .zeroserve/scripts/ is compiled into .o
 *   and only the .o is included in the output tarball.
 */
#ifndef ZEROSERVE_SDK_ZEROSERVE_H
#define ZEROSERVE_SDK_ZEROSERVE_H

typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char uint8_t;
typedef char int8_t;

#define ZS_SECTION(name) __attribute__((section(name)))
#define ZS_ENTRY ZS_SECTION("zeroserve.request")
#define ZS_INLINE __attribute__((always_inline))

typedef uint64_t zs_u64;
typedef int64_t zs_s64;
typedef uint32_t zs_u32;
typedef int32_t zs_s32;
typedef uint16_t zs_u16;
typedef int16_t zs_s16;
typedef uint8_t zs_u8;
typedef int8_t zs_s8;

extern zs_s64 zs_log(const char *msg, zs_u64 len);
extern zs_u64 zs_date(void);
extern zs_u64 zs_now_ms(void);

extern zs_s64 zs_req_method(char *out, zs_u64 out_len);
extern zs_s64 zs_req_path(char *out, zs_u64 out_len);
extern zs_s64 zs_req_uri(char *out, zs_u64 out_len);
extern zs_s64 zs_req_query(char *out, zs_u64 out_len);
extern zs_s64 zs_req_scheme(char *out, zs_u64 out_len);
extern zs_s64 zs_req_peer(char *out, zs_u64 out_len);
extern zs_s64 zs_req_header(
    const char *name,
    zs_u64 name_len,
    char *out,
    zs_u64 out_len);
extern zs_s64 zs_req_query_param(
    const char *name,
    zs_u64 name_len,
    char *out,
    zs_u64 out_len);

extern zs_s64 zs_meta_get(
    const char *key,
    zs_u64 key_len,
    char *out,
    zs_u64 out_len);
extern zs_s64 zs_meta_set(
    const char *key,
    zs_u64 key_len,
    const char *value,
    zs_u64 value_len);

extern zs_s64 zs_respond(
    zs_u64 status,
    const void *body,
    zs_u64 body_len,
    const char *content_type,
    zs_u64 content_type_len);

#endif
