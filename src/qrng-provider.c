// qrng-provider.c
#include "qrng-provider.h"

// Define the provider name
#define QRNG_PROV_NAME "RQRNG"

// External declaration of RNG functions
extern const OSSL_DISPATCH qrng_rand_functions[];

// Define the RNG algorithm
static const OSSL_ALGORITHM qrng_rands[] = {
    { "CTR-DRBG", NULL, qrng_rand_functions, "Remote Quantum Random Number Generation" },
    { NULL, NULL, NULL }
};

// Query operation function
static const OSSL_ALGORITHM *qrng_query_operation(void *provctx, int operation_id, int *no_store)
{
    switch (operation_id)
    {
    case OSSL_OP_RAND:
        return qrng_rands;
    default:
        fprintf(stderr, "QRNG provider> returning nothing, no algo matches op id %d\n", operation_id);
        return NULL;
    }
}

// Unquery operation function
static void qrng_unquery_operation(void *provctx, int operation_id, const OSSL_ALGORITHM *alg)
{
    if (operation_id != OSSL_OP_RAND)
        OPENSSL_free((void *)alg);
}

// Get provider parameters
static int qrng_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QRNG_PROV_NAME))
        return 0;

    // Add other provider parameters if necessary

    return 1;
}

// Dispatch table for provider functions
static const OSSL_DISPATCH qrng_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))qrng_query_operation },
    { OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))qrng_unquery_operation },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))qrng_get_params },
    { 0, NULL }
};

// Provider initialization function
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                       void **provctx)
{
    QRNG_PROVIDER_CTX *cprov;

    // Allocate and initialize provider context
    cprov = OPENSSL_zalloc(sizeof(QRNG_PROVIDER_CTX));
    if (cprov == NULL)
        return 0;

    // Initialize provider context fields if necessary
    cprov->core = handle;
    cprov->libctx = NULL; // or initialize as needed

    *out = qrng_dispatch_table;

    return 1;
}
