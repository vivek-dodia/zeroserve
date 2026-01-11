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
 * - If a script calls zs_reverse_proxy, the request is proxied and later
 *   scripts are skipped.
 * - Script failures are logged and do not abort the chain.
 *
 * Data access:
 * - Request data is read via zs_req_* helpers (method, path, uri, query,
 *   scheme, peer, headers, query params).
 * - Request mutations are applied with zs_req_set_uri/zs_req_set_header and
 *   are visible to later scripts and reverse proxy backends.
 * - Passing value_len=0 to zs_req_set_header removes the header.
 * - Header names are matched case-insensitively (stored lowercase internally).
 * - zs_meta_get/zs_meta_set expose a per-request string map shared by scripts.
 *
 * Helper I/O:
 * - String helpers write a C string into the provided buffer.
 * - Passing out_len=0 returns the required length for the value.
 * - zs_log writes to the server log, buffering until a newline or ~512 bytes.
 * - zs_date / zs_now_ms return milliseconds since the Unix epoch.
 * - zs_reverse_proxy forwards the request to a backend URL.
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
typedef unsigned long size_t;
typedef long ssize_t;

#define ZS_SECTION(name) __attribute__((section(name)))
#define ZS_ENTRY ZS_SECTION("zeroserve.request")
#define ZS_INLINE __attribute__((always_inline))
#define ZS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ZS_MAX(a, b) ((a) > (b) ? (a) : (b))

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
extern zs_s64 zs_req_set_uri(const char *uri, zs_u64 uri_len);
extern zs_s64 zs_req_query(char *out, zs_u64 out_len);
extern zs_s64 zs_req_scheme(char *out, zs_u64 out_len);
extern zs_s64 zs_req_peer(char *out, zs_u64 out_len);
extern zs_s64 zs_req_header(
    const char *name,
    zs_u64 name_len,
    char *out,
    zs_u64 out_len);
extern zs_s64 zs_req_set_header(
    const char *name,
    zs_u64 name_len,
    const char *value,
    zs_u64 value_len);
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

extern zs_s64 zs_reverse_proxy(
    const char *backend_url,
    zs_u64 backend_url_len);

static ZS_INLINE void *zs_memcpy(void *dst, const void *src, size_t n)
{
    zs_u8 *d = (zs_u8 *)dst;
    const zs_u8 *s = (const zs_u8 *)src;

    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static ZS_INLINE int zs_memcmp(const void *a, const void *b, size_t n)
{
    const zs_u8 *pa = (const zs_u8 *)a;
    const zs_u8 *pb = (const zs_u8 *)b;

    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return (int)pa[i] - (int)pb[i];
    }
    return 0;
}

static ZS_INLINE void *zs_memset(void *dst, int c, size_t n)
{
    zs_u8 *d = (zs_u8 *)dst;
    zs_u8 v = (zs_u8)c;

    for (size_t i = 0; i < n; i++) d[i] = v;
    return dst;
}

static ZS_INLINE char *zs_strncpy(char *dst, const char *src, size_t n)
{
    size_t i = 0;

    for (; i < n && src[i] != '\0'; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}

static ZS_INLINE char *zs_strcpy(char *dst, const char *src)
{
    size_t i = 0;

    while (src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}

static ZS_INLINE char *zs_stpcpy(char *dst, const char *src)
{
    size_t i = 0;

    while (src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst + i;
}

static ZS_INLINE int zs_strcmp(const char *a, const char *b)
{
    size_t i = 0;

    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        i++;
    }
    return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
}

static ZS_INLINE int zs_strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

static ZS_INLINE size_t zs_strlen(const char *s)
{
    size_t len = 0;

    while (s[len] != '\0') len++;
    return len;
}

static ZS_INLINE int zs_utoa10(unsigned int value, char *out, size_t out_size)
{
    /* Need at least 2 bytes for "0" + '\0' */
    if (!out || out_size < 2) return -1;

    /* Special case: value == 0 */
    if (value == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }

    /* First, count digits */
    unsigned int tmp = value;
    size_t digits = 0;
    while (tmp > 0) {
        tmp /= 10;
        digits++;
    }

    /* Ensure buffer can hold digits + null terminator */
    if (digits + 1 > out_size) return -1;

    /* Write digits from the end */
    out[digits] = '\0';
    size_t i = digits;
    while (value > 0) {
        unsigned int digit = value % 10;
        value /= 10;
        out[--i] = (char)('0' + digit);
    }

    return (int)digits;
}

#endif
