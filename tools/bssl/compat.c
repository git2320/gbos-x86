// SPDX-License-Identifier: Apache-2.0
/*
 * One-shot SHA helpers and FIPS stubs. Google's (and older AOSP) libcrypto
 * export SHA1/SHA224/SHA256/SHA384/SHA512/SHA512_256 as external symbols;
 * upstream BoringSSL made them static inline in sha.h, so AOSP binaries that
 * reference them dynamically fail to link. Export them here via the EVP API.
 *
 * Do NOT include <openssl/sha.h>: it defines these as `static inline`, which
 * collides with the definitions below. Digest lengths are hardcoded instead.
 */
#include <string.h>

/* crypto.h pulls in sha.h, which declares these as static inline; avoid it. */
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SHA_DIGEST_LENGTH_ 20
#define SHA224_DIGEST_LENGTH_ 28
#define SHA256_DIGEST_LENGTH_ 32
#define SHA384_DIGEST_LENGTH_ 48
#define SHA512_DIGEST_LENGTH_ 64

#define EXPORT __attribute__((visibility("default")))

/* Prototypes (headers intentionally avoided; see note above). */
EXPORT uint8_t *SHA1(const uint8_t *data, size_t len, uint8_t *out);
EXPORT uint8_t *SHA224(const uint8_t *data, size_t len, uint8_t *out);
EXPORT uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t *out);
EXPORT uint8_t *SHA384(const uint8_t *data, size_t len, uint8_t *out);
EXPORT uint8_t *SHA512(const uint8_t *data, size_t len, uint8_t *out);
EXPORT uint8_t *SHA512_256(const uint8_t *data, size_t len, uint8_t *out);
EXPORT int BORINGSSL_integrity_test(void);
EXPORT const uint8_t *FIPS_module_hash(void);
EXPORT void RAND_maybe_reseed(void);
EXPORT void HMAC_CTX_init(void *ctx);
EXPORT void HMAC_CTX_cleanup(void *ctx);
EXPORT void *HMAC_CTX_new(void);
EXPORT void HMAC_CTX_free(void *ctx);
EXPORT void HMAC_CTX_cleanse(void *ctx);
EXPORT int HMAC_Init_ex(void *ctx, const void *key, size_t key_len,
                        const void *md, void *impl);
EXPORT int HMAC_Update(void *ctx, const uint8_t *data, size_t len);
EXPORT int HMAC_Final(void *ctx, uint8_t *out, unsigned int *out_len);
EXPORT size_t HMAC_size(const void *ctx);
EXPORT const void *HMAC_CTX_get_md(const void *ctx);
EXPORT int HMAC_CTX_copy_ex(void *dst, const void *src);
EXPORT void HMAC_CTX_reset(void *ctx);
EXPORT int HMAC_Init(void *ctx, const void *key, int key_len, const void *md);
EXPORT int HMAC_CTX_copy(void *dst, const void *src);

/* Each returns the destination buffer, matching the legacy AOSP signature. */
static uint8_t *digest_one_shot(const EVP_MD *md, const uint8_t *data,
                                size_t len, uint8_t *out, size_t outlen)
{
    unsigned int actual = 0;

    if (!EVP_Digest(data, len, out, &actual, md, NULL) || actual != outlen)
        return NULL;
    return out;
}

EXPORT uint8_t *SHA1(const uint8_t *data, size_t len, uint8_t *out)
{
    return digest_one_shot(EVP_sha1(), data, len, out, SHA_DIGEST_LENGTH_);
}

EXPORT uint8_t *SHA224(const uint8_t *data, size_t len, uint8_t *out)
{
    return digest_one_shot(EVP_sha224(), data, len, out, SHA224_DIGEST_LENGTH_);
}

EXPORT uint8_t *SHA256(const uint8_t *data, size_t len, uint8_t *out)
{
    return digest_one_shot(EVP_sha256(), data, len, out, SHA256_DIGEST_LENGTH_);
}

EXPORT uint8_t *SHA384(const uint8_t *data, size_t len, uint8_t *out)
{
    return digest_one_shot(EVP_sha384(), data, len, out, SHA384_DIGEST_LENGTH_);
}

EXPORT uint8_t *SHA512(const uint8_t *data, size_t len, uint8_t *out)
{
    return digest_one_shot(EVP_sha512(), data, len, out, SHA512_DIGEST_LENGTH_);
}

/* SHA-512/256: SHA-512 IV with different initial state, truncated to 32 bytes.
 * EVP has no direct SHA512_256 in all versions; use SHA512 and truncate only
 * if unavailable. Google's symbol uses the NIST SHA-512/256 domain, so prefer
 * EVP_sha512_256 when present. */
EXPORT uint8_t *SHA512_256(const uint8_t *data, size_t len, uint8_t *out)
{
    const EVP_MD *md = EVP_sha512_256();
    uint8_t full[SHA512_DIGEST_LENGTH_];

    if (md != NULL)
        return digest_one_shot(md, data, len, out, 32);

    if (digest_one_shot(EVP_sha512(), data, len, full, SHA512_DIGEST_LENGTH_) == NULL)
        return NULL;
    memcpy(out, full, 32);
    return out;
}

/* Legacy FIPS/FIPS-module helpers kept for symbol compatibility. */
EXPORT int BORINGSSL_integrity_test(void)
{
    return 1;
}

EXPORT const uint8_t *FIPS_module_hash(void)
{
    static const uint8_t zeros[SHA256_DIGEST_LENGTH_];
    return zeros;
}

EXPORT void RAND_maybe_reseed(void)
{
    /* Nothing to do: the DRBG reseeds itself. */
}

/*
 * ABI shims for the legacy stack-based HMAC_CTX API.
 *
 * Google's BoringSSL has a 704-byte HMAC_CTX; ours is 800 bytes. Android
 * libraries (e.g. libkeymaster_portable.so) stack-allocate the old size and
 * call HMAC_CTX_init, so our functions would write past the buffer and trip
 * -fstack-protector. Internally, BoringSSL's stack HMAC functions were renamed
 * to bssl_real_* (see hmac.cc.inc); these shims allocate a real heap context
 * and stash the pointer in the caller's buffer instead.
 */
struct hmac_shim { void *real; };

/* The real (renamed) implementations inside libcrypto. */
extern void bssl_real_HMAC_CTX_init(void *ctx);
extern void bssl_real_HMAC_CTX_cleanup(void *ctx);
extern void bssl_real_HMAC_CTX_cleanse(void *ctx);
extern int bssl_real_HMAC_Init_ex(void *ctx, const void *key, size_t key_len,
                                  const void *md, void *impl);
extern int bssl_real_HMAC_Update(void *ctx, const uint8_t *data, size_t len);
extern int bssl_real_HMAC_Final(void *ctx, uint8_t *out, unsigned int *out_len);
extern void *bssl_real_HMAC_CTX_new(void);
extern void bssl_real_HMAC_CTX_free(void *ctx);
extern size_t bssl_real_HMAC_size(const void *ctx);
extern const void *bssl_real_HMAC_CTX_get_md(const void *ctx);
extern int bssl_real_HMAC_CTX_copy_ex(void *dst, const void *src);
extern void bssl_real_HMAC_CTX_reset(void *ctx);
extern int bssl_real_HMAC_Init(void *ctx, const void *key, int key_len,
                               const void *md);
extern int bssl_real_HMAC_CTX_copy(void *dst, const void *src);

static void *hmac_shim_real(void *ctx)
{
    return ctx ? ((struct hmac_shim *)ctx)->real : NULL;
}

EXPORT void HMAC_CTX_init(void *ctx)
{
    ((struct hmac_shim *)ctx)->real = bssl_real_HMAC_CTX_new();
}

EXPORT void HMAC_CTX_cleanup(void *ctx)
{
    void *real = hmac_shim_real(ctx);
    if (real) {
        bssl_real_HMAC_CTX_free(real);
        ((struct hmac_shim *)ctx)->real = NULL;
    }
}

EXPORT void *HMAC_CTX_new(void)
{
    struct hmac_shim *s = malloc(sizeof(*s));
    if (s)
        s->real = bssl_real_HMAC_CTX_new();
    if (s && !s->real) { free(s); s = NULL; }
    return s;
}

EXPORT void HMAC_CTX_free(void *ctx)
{
    if (!ctx) return;
    bssl_real_HMAC_CTX_free(hmac_shim_real(ctx));
    free(ctx);
}

EXPORT void HMAC_CTX_cleanse(void *ctx)
{
    void *real = hmac_shim_real(ctx);
    if (real)
        bssl_real_HMAC_CTX_cleanse(real);
}

EXPORT int HMAC_Init_ex(void *ctx, const void *key, size_t key_len,
                        const void *md, void *impl)
{
    void *real = hmac_shim_real(ctx);
    return bssl_real_HMAC_Init_ex(real, key, key_len, md, impl);
}

EXPORT int HMAC_Update(void *ctx, const uint8_t *data, size_t len)
{
    return bssl_real_HMAC_Update(hmac_shim_real(ctx), data, len);
}

EXPORT int HMAC_Final(void *ctx, uint8_t *out, unsigned int *out_len)
{
    return bssl_real_HMAC_Final(hmac_shim_real(ctx), out, out_len);
}

EXPORT size_t HMAC_size(const void *ctx)
{
    return bssl_real_HMAC_size(hmac_shim_real((void *)ctx));
}

EXPORT const void *HMAC_CTX_get_md(const void *ctx)
{
    return bssl_real_HMAC_CTX_get_md(hmac_shim_real((void *)ctx));
}

EXPORT int HMAC_CTX_copy_ex(void *dst, const void *src)
{
    void *s = hmac_shim_real((void *)src);
    void *d = hmac_shim_real(dst);
    if (!d) { HMAC_CTX_init(dst); d = hmac_shim_real(dst); }
    return bssl_real_HMAC_CTX_copy_ex(d, s);
}

EXPORT void HMAC_CTX_reset(void *ctx)
{
    bssl_real_HMAC_CTX_reset(hmac_shim_real(ctx));
}

EXPORT int HMAC_Init(void *ctx, const void *key, int key_len, const void *md)
{
    return bssl_real_HMAC_Init(hmac_shim_real(ctx), key, key_len, md);
}

EXPORT int HMAC_CTX_copy(void *dst, const void *src)
{
    void *s = hmac_shim_real((void *)src);
    if (!hmac_shim_real(dst)) HMAC_CTX_init(dst);
    return bssl_real_HMAC_CTX_copy(hmac_shim_real(dst), s);
}
