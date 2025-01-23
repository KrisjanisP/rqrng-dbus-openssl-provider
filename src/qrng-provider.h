// qrng-provider.h
#ifndef QRNG_PROVIDER_H
#define QRNG_PROVIDER_H

#include <systemd/sd-bus.h>
#include <openssl/provider.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

// Define DBG for debugging (enable as needed)
#define DBG(...) /* fprintf(stderr, __VA_ARGS__); fflush(stderr) */

// Forward declaration of QRNG_RAND_CTX
typedef struct qrng_rand_ctx_st QRNG_RAND_CTX;

// Definition of QRNG_RAND_CTX
struct qrng_rand_ctx_st {
    CRYPTO_RWLOCK *lock;
    int state;
    sd_bus *bus;  // Add D-Bus connection=
};

// Forward declaration of QRNG_PROVIDER_CTX
typedef struct qrng_provider_ctx_st QRNG_PROVIDER_CTX;

// Definition of QRNG_PROVIDER_CTX
struct qrng_provider_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
    // Add any additional fields as necessary
};

// Function prototypes
// Add any necessary function prototypes here

#endif // QRNG_PROVIDER_H
