// qrng-provider-rand.c
#include "qrng-provider.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/random.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

// #define DEVICE_NAME "/home/kpetrucena/Programming/krisjanisp-github/rqrng-dbus-openssl-provider/README.md"
#define DEVICE_NAME "/dev/random"
#define QRNG_MAX_READ_SIZE 65536 // Define a suitable maximum read size

extern int errno;

// Fallback function using getrandom
static int fallback_rand_bytes(unsigned char *out, size_t count) {
    ssize_t n = getrandom(out, count, 0);
    if (n != count) {
        fprintf(stderr, "Error: read only %zd bytes out of %zu\n", n, count);
        return 0;
    }
    return 1;
}

// Generate function with error handling
static int
qrng_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                   unsigned int strength, int prediction_resistance,
                   const unsigned char *adin, size_t adinlen)
{
    ssize_t bytes_read = 0;
    int fd = open(DEVICE_NAME, O_RDONLY);

    if (fd == -1) {
        perror("Failed to open device, falling back to getrandom");
        return fallback_rand_bytes(out, outlen);
    }

    bytes_read = read(fd, out, outlen);
    close(fd);

    if (bytes_read != outlen) {
        fprintf(stderr, "Failed to read enough bytes: expected %zu, got %zd. Falling back to getrandom.\n", outlen, bytes_read);
        return fallback_rand_bytes(out, outlen);
    }

    return 1;
}

// Context creation
static void *
qrng_rand_newctx(void *provctx, void *parent,
                const OSSL_DISPATCH *parent_calls)
{
    QRNG_RAND_CTX *rand = OPENSSL_zalloc(sizeof(QRNG_RAND_CTX));
    if (rand == NULL)
        return NULL;

    rand->lock = CRYPTO_THREAD_lock_new();
    if (rand->lock == NULL) {
        OPENSSL_clear_free(rand, sizeof(QRNG_RAND_CTX));
        return NULL;
    }

    rand->state = EVP_RAND_STATE_UNINITIALISED;
    return rand;
}

// Context freeing
static void
qrng_rand_freectx(void *ctx)
{
    QRNG_RAND_CTX *rand = ctx;

    if (rand == NULL)
        return;

    CRYPTO_THREAD_lock_free(rand->lock);
    OPENSSL_clear_free(rand, sizeof(QRNG_RAND_CTX));
}

// Instantiate RNG
static int
qrng_rand_instantiate(void *ctx, unsigned int strength,
                      int prediction_resistance,
                      const unsigned char *pstr, size_t pstr_len,
                      const OSSL_PARAM params[])
{
    QRNG_RAND_CTX *qrng_ctx = ctx;
    qrng_ctx->state = EVP_RAND_STATE_READY;
    return 1;
}

// Uninstantiate RNG
static int
qrng_rand_uninstantiate(void *ctx)
{
    QRNG_RAND_CTX *qrng_ctx = ctx;
    qrng_ctx->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

// Enable locking
static int
qrng_rand_enable_locking(void *ctx)
{
    QRNG_RAND_CTX *rand = ctx;
    if (rand == NULL)
        return 0;

    if (rand->lock == NULL) {
        rand->lock = CRYPTO_THREAD_lock_new();
        if (rand->lock == NULL)
            return 0;
    }

    return 1;
}

// Lock
static int
qrng_rand_lock(void *ctx)
{
    QRNG_RAND_CTX *rand = ctx;

    if (rand == NULL || rand->lock == NULL)
        return 1;

    return CRYPTO_THREAD_write_lock(rand->lock);
}

// Unlock
static void qrng_rand_unlock(void *ctx)
{
    QRNG_RAND_CTX *rand = ctx;

    if (rand == NULL || rand->lock == NULL)
        return;
    CRYPTO_THREAD_unlock(rand->lock);
}

// Gettable context parameters
static const OSSL_PARAM *qrng_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_int(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

// Get context parameters
static int qrng_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, QRNG_MAX_READ_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_int(p, 8 * QRNG_MAX_READ_SIZE))
        return 0;

    return 1;
}

// Settable context parameters (none in this case)
static const OSSL_PARAM *qrng_rand_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

// Set context parameters (no-op)
static int qrng_rand_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return 1;
}

// Reseed function (no-op)
static int qrng_rand_reseed(void *ctx, unsigned int reseed_counter,
                            const unsigned char *adin, size_t adinlen)
{
    return 1;
}

// Dispatch table for RNG functions
const OSSL_DISPATCH qrng_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))qrng_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))qrng_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))qrng_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))qrng_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))qrng_rand_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))qrng_rand_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))qrng_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))qrng_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))qrng_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))qrng_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))qrng_rand_get_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void))qrng_rand_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))qrng_rand_set_ctx_params },
    { 0, NULL }
};
