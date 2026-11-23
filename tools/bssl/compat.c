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
