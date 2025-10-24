#include "internal.h"

#if OPENSSL_VERSION_MAJOR > 1
#include <openssl/provider.h>

OSSL_PROVIDER *legacy;
OSSL_PROVIDER *deflt;

void load_legacy_module() {
    legacy = NULL;
    deflt = NULL;

    LOG_INFO(("Enable legacy provider\n"))

    /* Load Multiple providers into the default (NULL) library context */
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy == NULL) {
        LOG_ERROR(("Failed to load legacy provider\n"))
        exit(EXIT_FAILURE);
    }

    deflt = OSSL_PROVIDER_load(NULL, "default");
    if (deflt == NULL) {
        LOG_ERROR(("Failed to load default provider\n"))
        OSSL_PROVIDER_unload(legacy);
        exit(EXIT_FAILURE);
    }
}

void free_legacy_module() {
    if(legacy) {
        OSSL_PROVIDER_unload(legacy);
    }

    if(deflt) {
        OSSL_PROVIDER_unload(deflt);
    }
}

#else
void load_legacy_module() {}
void free_legacy_module() {}
#endif

char *oss_err_as_string (void) { 
    BIO *bio = BIO_new (BIO_s_mem ());
    ERR_print_errors (bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data (bio, &buf);
    char *ret = (char *) calloc (1, 1 + len);
    if (ret)
        memcpy (ret, buf, len);
    BIO_free (bio);
    return ret;
}

void oss_print_error() {
    LOG_DEBUG(("This is the openssl specific error\n"))
    char *ossl_err = oss_err_as_string();
    LOG_DEBUG(("%s\n", ossl_err))
    free(ossl_err);
}

void oss_load_implicit_ta(const char *chain_pem, ESTClient_Options_t *opts) {
    // Load all certificates in CACHAIN (used to validate EST server https endpoint).
    size_t chain_pem_len = strlen(chain_pem);

    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, chain_pem, chain_pem_len);

    size_t chain_mem_len = 100; // very very large, impossibile to have a huge chain like this!
    opts->chain = (ESTCertificate_t **)malloc(sizeof(ESTCertificate_t *) * chain_mem_len);
    if (opts->chain == NULL) {
        LOG_ERROR(("Memory allocation failed\n"))
        exit(EXIT_FAILURE);
    }
    opts->chain_len = 0;

    X509 *crt = NULL;
    do {
        crt = PEM_read_bio_X509(mem, NULL, NULL, NULL);
        if(crt != NULL) {
            opts->chain[opts->chain_len++] = (ESTCertificate_t *)crt;
        }
    } while(crt != NULL);

    LOG_INFO(("Implicit TA loading completed. Certificate number %d\n", (int)opts->chain_len))

    BIO_free(mem);
}

void oss_free_implicit_ta(ESTClient_Options_t *opts) {
    for(int i = 0; i < opts->chain_len; i++) {
        X509_free((X509 *)opts->chain[i]);
    }
    free(opts->chain);
    opts->chain = NULL;
}

int oss_crt2pem_noterminator(X509 *crt, char *pem, size_t pem_len) {
    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, crt);
    
    // get buffer len
    BUF_MEM *bptr;
    BIO_get_mem_ptr(mem, &bptr);
    int length = bptr->length;

    int num = BIO_read(mem, pem, length);
    BIO_free(mem);
    return num;
}