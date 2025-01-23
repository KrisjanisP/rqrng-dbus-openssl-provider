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
#include <systemd/sd-bus.h>
#include <openssl/crypto.h>

// #define DEVICE_NAME "/home/kpetrucena/Programming/krisjanisp-github/rqrng-dbus-openssl-provider/README.md"
#define DEVICE_NAME "/dev/random"
#define QRNG_MAX_READ_SIZE 65536 // Define a suitable maximum read size

extern int errno;

// Function to get random bytes via D-Bus
static int dbus_get_random_bytes(sd_bus *bus, unsigned char *out, size_t outlen) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int ret;

    // Make the D-Bus method call
    ret = sd_bus_call_method(
        bus,
        "lv.lumii.qrng",                             // Service
        "/lv/lumii/qrng/RemoteQrngXorLinuxRng",      // Object path
        "lv.lumii.qrng.Rng",                         // Interface
        "GenerateOctets",                            // Method
        &error,
        &reply,
        "t",                                         // Input signature
        (uint32_t)outlen                             // Number of bytes requested
    );

    if (ret < 0) {
        fprintf(stderr, "Failed to call D-Bus method: %s\n", error.message);
        sd_bus_error_free(&error);
        return 0;
    }

    // Parse the reply
    uint32_t status;
    ret = sd_bus_message_read(reply, "u", &status);
    if (ret < 0 || status != 0) {
        sd_bus_error_free(&error);
        sd_bus_message_unref(reply);
        return 0;
    }

    // Read the array of bytes
    const void *ptr;
    size_t received_len;
    ret = sd_bus_message_read_array(reply, 'y', &ptr, &received_len);
    if (ret < 0 || received_len != outlen) {
        sd_bus_error_free(&error);
        sd_bus_message_unref(reply);
        return 0;
    }

    // Copy the received bytes to the output buffer
    memcpy(out, ptr, outlen);

    sd_bus_error_free(&error);
    sd_bus_message_unref(reply);
    return 1;
}

// Fallback function using getrandom
static int fallback_rand_bytes(unsigned char *out, size_t count) {
    ssize_t n = getrandom(out, count, 0);
    if (n != count) {
        fprintf(stderr, "Error: read only %zd bytes out of %zu\n", n, count);
        return 0;
    }
    return 1;
}

// Modify the generate function to use D-Bus
static int
qrng_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                   unsigned int strength, int prediction_resistance,
                   const unsigned char *adin, size_t adinlen)
{
    QRNG_RAND_CTX *qrng_ctx = ctx;
    
    // Try to get random bytes via D-Bus
    if (qrng_ctx->bus != NULL) {
        if (dbus_get_random_bytes(qrng_ctx->bus, out, outlen)) {
            return 1;
        }
    }

    // Fall back to getrandom if D-Bus fails
    return fallback_rand_bytes(out, outlen);
}

// Modify the context creation to initialize D-Bus
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

    // Initialize D-Bus connection
    if (sd_bus_open_user(&rand->bus) < 0) {
        fprintf(stderr, "Failed to connect to D-Bus, will fall back to getrandom\n");
        rand->bus = NULL;
    }

    rand->state = EVP_RAND_STATE_UNINITIALISED;
    return rand;
}

// Modify context freeing to clean up D-Bus
static void
qrng_rand_freectx(void *ctx)
{
    QRNG_RAND_CTX *rand = ctx;

    if (rand == NULL)
        return;

    if (rand->bus != NULL)
        sd_bus_unref(rand->bus);
    
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
