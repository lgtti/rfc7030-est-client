#include "internal.h"

/**
 * @brief Read privat key from file
 *
 * @param filename: path to private key
 *
 * @return ESTPrivKey_T
 */
ESTPrivKey_t *read_private_key(const char *filename)
{
    if (filename == NULL)
    {
        printf("\nError: filename is NULL\n");
        return NULL;
    }
    
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    mbedtls_pk_context *pkey = (mbedtls_pk_context *)malloc(sizeof(mbedtls_pk_context));
    if (pkey == NULL)
    {
        printf("\nError: failed to read private key\n");
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return NULL;
    }
    mbedtls_pk_init(pkey);
    mbedtls_pk_parse_keyfile(pkey, filename, NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    
    return (ESTPrivKey_t *)pkey;
}

ESTCertificate_t * pf2crt(const char *name) {
    if (name == NULL)
    {
        return NULL;
    }
    FILE *pf = fopen(name, "rt");
    if (!pf) {
        printf("Failed to open %s from resource file\n", name);
        exit(EXIT_FAILURE);
    }
    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (cert == NULL) {
        fclose(pf);
        return NULL;
    }
    mbedtls_x509_crt_init(cert);
    if (mbedtls_x509_crt_parse_file(cert, name) != 0) {
        printf("Failed to parse certificate file\n");
        fclose(pf);
        mbedtls_x509_crt_free(cert);
        free(cert);
        return NULL;
    }
    fclose(pf);
    return (ESTCertificate_t *)cert;
}

int crt_equals(ESTCertificate_t *received, ESTCertificate_t *expected) {
    if (received == NULL || expected == NULL)
    {
        return 0;
    }
    mbedtls_x509_crt *rec = (mbedtls_x509_crt *)received;
    mbedtls_x509_crt *exp = (mbedtls_x509_crt *)expected;

    if (rec->raw.len != exp->raw.len)
    {
        return 0;
    }

    if (memcmp(rec->raw.p, exp->raw.p, rec->raw.len) != 0)
    {
        return 0;
    }
    return 1;
}

ESTCertificate_t * pem2crt(const char *pem) {
    if (pem == NULL)
    {
        return NULL;
    }
    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (cert == NULL) {
        return NULL;
    }
    mbedtls_x509_crt_init(cert);
    mbedtls_x509_crt_parse(cert, (const unsigned char *)pem, strlen(pem) + 1);
    return (ESTCertificate_t *)cert;
}


bool_t is_issuer(mbedtls_x509_crt *issuer, mbedtls_x509_crt *crt) {  
    if (issuer == NULL || crt == NULL) {  
        return EST_FALSE;  
    }  

    // Create a new certificate verification context  
    mbedtls_x509_crt *cert = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));  
    if (cert == NULL) {  
        return EST_FALSE;  
    }  
    mbedtls_x509_crt_init(cert);  

    // Parse the issuer certificate  
    if (mbedtls_x509_crt_parse(cert, issuer->raw.p, issuer->raw.len) != 0) {  
        mbedtls_x509_crt_free(cert);  
        return EST_FALSE;  
    }  

    // Verify the certificate  
    int ret = mbedtls_x509_crt_verify(crt, cert, NULL, NULL, NULL, NULL, NULL);  
    if (ret != 0) {  
        char error_buf[100] = {0};  
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));  
        printf("Verification failed: %s\n", error_buf);  
        mbedtls_x509_crt_free(cert);  
        return EST_FALSE;  
    }  

    // Free resources  
    mbedtls_x509_crt_free(cert);  
    return EST_TRUE;  
}

bool_t pop_create_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err) {
    int ret;
    char *pkeyfilename = (char *)ctx;
    mbedtls_pk_context *pkey = read_private_key(pkeyfilename);

    mbedtls_x509write_csr *write_csr = malloc(sizeof(mbedtls_x509write_csr));;
    mbedtls_x509write_csr_init(write_csr);

    char subject[] = "C=India,O=Schneider,CN=TestClient"; 
    mbedtls_x509write_csr_set_md_alg(write_csr, MBEDTLS_MD_SHA256);

    // Set the subject name
    if ((ret = mbedtls_x509write_csr_set_subject_name(write_csr, (const char*) subject)) != 0)
    {
        LOG_DEBUG(("Failed to set subject name"))
        mbedtls_x509write_csr_free(write_csr);
        mbedtls_pk_free(pkey);
        return EST_FALSE;
    }

    // Set key
    mbedtls_x509write_csr_set_key(write_csr, pkey);    

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    // Initialize the entropy and CTR_DRBG contexts
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the CTR_DRBG context
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        oss_print_error(ret);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return EST_FALSE;
    }

    ret = mbedtls_x509write_csr_pem(write_csr, csr, csr_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0)
    {
        oss_print_error(ret);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        return EST_FALSE;
    }

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return EST_TRUE;
}