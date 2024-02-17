// hmac_sha256.cpp
// Originally written in C by https://github.com/h5p9sl

#include "hmac_sha256.h"
#include "sha256.h"

#include <cstring> // For std::memcpy
#include <vector>  // For std::vector

constexpr size_t SHA256_BLOCK_SIZE = 64;

// LOCAL FUNCTIONS

// Concatenate X & Y, return hash.
static void *H(const void *x,
               const size_t xlen,
               const void *y,
               const size_t ylen,
               void *out,
               const size_t outlen);

// Wrapper for sha256
static void *sha256(const void *data,
                    const size_t datalen,
                    void *out,
                    const size_t outlen);

// Declared in hmac_sha256.h
size_t hmac_sha256(const void *key,
                   const size_t keylen,
                   const void *data,
                   const size_t datalen,
                   void *out,
                   const size_t outlen)
{
    std::vector<uint8_t> k(SHA256_BLOCK_SIZE, 0);
    std::vector<uint8_t> k_ipad(SHA256_BLOCK_SIZE, 0x36);
    std::vector<uint8_t> k_opad(SHA256_BLOCK_SIZE, 0x5c);
    uint8_t ihash[SHA256_HASH_SIZE];
    uint8_t ohash[SHA256_HASH_SIZE];
    size_t sz;

    if (keylen > SHA256_BLOCK_SIZE)
    {
        // If the key is larger than the hash algorithm's
        // block size, we must digest it first.
        sha256(key, keylen, k.data(), k.size());
    }
    else
    {
        std::memcpy(k.data(), key, keylen);
    }

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; ++i)
    {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
    //      `H(K XOR opad, H(K XOR ipad, data))`
    H(k_ipad.data(), k_ipad.size(), data, datalen, ihash, sizeof(ihash));
    H(k_opad.data(), k_opad.size(), ihash, sizeof(ihash), ohash, sizeof(ohash));

    sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    std::memcpy(out, ohash, sz);
    return sz;
}

static void *H(const void *x,
               const size_t xlen,
               const void *y,
               const size_t ylen,
               void *out,
               const size_t outlen)
{
    size_t buflen = xlen + ylen;
    auto buf = new uint8_t[buflen];

    std::memcpy(buf, x, xlen);
    std::memcpy(buf + xlen, y, ylen);
    void *result = sha256(buf, buflen, out, outlen);

    delete[] buf;
    return result;
}

static void *sha256(const void *data,
                    const size_t datalen,
                    void *out,
                    const size_t outlen)
{
    Sha256Context ctx;
    SHA256_HASH hash;

    Sha256Initialise(&ctx);
    Sha256Update(&ctx, data, datalen);
    Sha256Finalise(&ctx, &hash);

    size_t sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    return std::memcpy(out, hash.bytes, sz);
}
