#include "internal.h"
#include "custom_config.h"

ESTCertificate_t * pf2crt(const char *name) {
    if (name == NULL)
    {
        return NULL;
    }
    FILE *pf = fopen(name, "rt");
    if (!pf) {
        LOG_ERROR(("Failed to open %s from resource file\n", name))
        exit(EXIT_FAILURE);
    }
    ESTCertificate_t *cert = (ESTCertificate_t *)PEM_read_X509(pf, NULL, NULL, NULL);
    fclose(pf);
    return cert;
}

ESTCertificate_t * pem2crt(const char *pem) {
    if (pem == NULL)
    {
        return NULL;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pem);
    return (ESTCertificate_t *)PEM_read_bio_X509(bio, NULL, NULL, NULL);
}

bool_t crt_equals(ESTCertificate_t *received, ESTCertificate_t *expected) {
    if (received == NULL || expected == NULL)
    {
        return EST_FALSE;
    }
    int ret = X509_cmp((X509 *)received, (X509 *)expected);
    return ret == 0 ? EST_TRUE : EST_FALSE;
}

bool_t is_issuer(ESTCertificate_t *issuer, ESTCertificate_t *crt) {
    if (issuer == NULL || crt == NULL)
    {
        return EST_FALSE;
    }
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, (X509 *)issuer);

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, (X509 *)crt, NULL);

    if(!X509_verify_cert(ctx)) {
        printf("%s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        return EST_FALSE;
    } else {
        return EST_TRUE;
    }
}

bool_t pop_create_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err) {
    char *pkeyfilename = (char *)ctx;

    LOG_DEBUG(("Create CSR with POP, key file=%s\n", pkeyfilename))

    FILE *pf = fopen(pkeyfilename, "rt");
    EVP_PKEY *pk = PEM_read_PrivateKey(pf, NULL, NULL, NULL);

    LOG_DEBUG(("Create new X509_REQ object\n"))

    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pk);

    LOG_DEBUG(("Set subject name and challengePassword attribute\n"))

    X509_NAME *x509Name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC, (const unsigned char *)"IT", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC, (const unsigned char *)"Rfc7030", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "OU", MBSTRING_ASC, (const unsigned char *)"EstClient", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC, (const unsigned char *)"IntegrationTest", -1, -1, 0);
    X509_REQ_set_subject_name(req, x509Name);
    X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, MBSTRING_ASC, (const unsigned char *)tlsunique, -1);

    LOG_DEBUG(("Sign csr\n"))

    X509_REQ_sign(req, pk, EVP_sha256());

    LOG_DEBUG(("Convert csr to PEM format\n"))

    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(mem, req);
    *csr_len = BIO_read(mem, csr, *csr_len);
    BIO_free(mem);
    X509_NAME_free(x509Name);
    EVP_PKEY_free(pk);


    EVP_PKEY_free(pk);
    fclose(pf);
    return EST_TRUE;
}

static size_t read_file(const char *name, const char *flags, char *output) {
    if (name == NULL || output == NULL) {
        return 0;
    }
    FILE *fp = fopen(name, flags);
    if(!fp) {        
        LOG_ERROR(("Failed to open %s from resource file\n", name))
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0L, SEEK_END);
    long fp_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    
    size_t res_len = fp_size;
    
    fread(output, res_len, 1, fp);
    output[res_len] = '\0';
    fclose(fp);

    LOG_DEBUG(("%s(%d): \n", name, (int)res_len))
    LOG_DEBUG(("%s\n", output))

    return res_len;
}

static bool_t write_file(const char *name, const char *flags, char *input) {
    if (name == NULL || input == NULL) {
        return EST_FALSE;
    }
    FILE *fp = fopen(name, flags);
    if(!fp) {        
        LOG_ERROR(("Failed to open %s from resource file\n", name))
        exit(EXIT_FAILURE);
    }

    int result = fputs(input, fp) != EOF;
    fclose(fp);
    return result;
}

/**
 * @brief Generate CSR
 *
 * @param pk: private key in ESTPrivKey_t template structure
 * @param challenge_password: challenge password for CSR
 * @param csr: pointer to CSR placeholder
 * @param csr_len: pointer to CSR length
 * @param err: pointer to error
 * 
 *
 * @return EST_TRUE (1)
 * @return EST_FALSE (0)
 */
bool_t generate_cert_req(ESTPrivKey_t* pk, char *challenge_password, char *csr, size_t *csr_len, ESTError_t *err) {
    if (csr == NULL || csr_len == NULL) {
        printf("\nError: csr is NULL\n");
        return EST_FALSE;
    }

    if (pk == NULL)
    {
        printf("\nError: private key is NULL\n");
        return EST_FALSE;
    }

    X509_REQ *req = X509_REQ_new();
    if (req == NULL)
    {
        printf("\nError while creating X509_REQ object\n");
        EVP_PKEY_free((EVP_PKEY *)pk);
        pk = NULL;
        return EST_FALSE;
    }
    if (0 > X509_REQ_set_pubkey(req, (EVP_PKEY *)pk))
    {
        printf("\nError while setting public key in X509_REQ object\n");
        X509_REQ_free(req);
        EVP_PKEY_free((EVP_PKEY *)pk);
        req = NULL;
        pk = NULL;
        return EST_FALSE;
    }

    X509_NAME *x509Name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC, (const unsigned char *)"NEW_CLIENT", -1, -1, 0);
    X509_REQ_set_subject_name(req, x509Name);


    // Add challenge password
    ASN1_STRING *tmp_os = ASN1_OCTET_STRING_new();
    tmp_os->type = V_ASN1_PRINTABLESTRING;
    int password_length = strlen(challenge_password);
    ASN1_STRING_set(tmp_os, (const unsigned char *)challenge_password, password_length);
    X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, tmp_os->type, tmp_os->data,
                              password_length);

    ASN1_STRING_free(tmp_os);

    if (0 > X509_REQ_sign(req, (EVP_PKEY *)pk, EVP_sha256()))
    {
        printf("\nError while signing X509_REQ object\n");
        X509_REQ_free(req);
        EVP_PKEY_free((EVP_PKEY *)pk);
        req = NULL;
        pk = NULL;
        return EST_FALSE;
    }

    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(mem, req);
    int len = BIO_pending(mem);
    if (len <= 0 || len >= *csr_len) {
        BIO_free(mem);
        return EST_FALSE;
    }
    BIO_read(mem, csr, len);
    csr[len] = '\0';
    *csr_len = len;
    BIO_free(mem);

    return EST_TRUE;
}

/**
 * @brief Generate CSR from previous enrolled certificate
 *
 * @param pk: private key in ESTPrivKey_t template structure
 * @param cert: previous enrolled certificate
 * @param challenge_password: challenge password for CSR
 * @param csr: pointer to CSR placeholder
 * @param csr_len: pointer to CSR length
 * @param err: pointer to error
 * 
 *
 * @return EST_TRUE (1)
 * @return EST_FALSE (0)
 */
bool_t generate_cert_req_from_enrolled_cert(ESTPrivKey_t* pk , char* cert, char *challenge_password, char *csr, size_t *csr_len, ESTError_t *err)
{
    if (cert == NULL)
    {
        printf("\nInvalid X509");
        return EST_FALSE;
    }
    ESTCertificate_t *enrolled_cert = pem2crt(cert);
    // We will sign csr later
    X509_REQ *req = X509_REQ_new();
    if (req == NULL)
    {
        printf("\nError while creating X509_REQ object\n");
        X509_REQ_free(req);
        return EST_FALSE;
    }    
    req = X509_to_X509_REQ((X509*)enrolled_cert, NULL, EVP_sha256());
    if (req == NULL)
    {
        printf("\nX509 to X509_REQ conversion failed\n");
        X509_REQ_free(req);
        req = NULL;
        return EST_FALSE;
    }

    if (X509_REQ_set_pubkey(req, (EVP_PKEY *)pk) == 0)
    {
        X509_REQ_free(req);
        req = NULL;  // necessary to clear global variable, before next re-enroll
        return EST_FALSE;
    }
    
    if (challenge_password != NULL)
    {
        // Add challenge password
        ASN1_STRING *tmp_os = ASN1_OCTET_STRING_new();
        tmp_os->type = V_ASN1_PRINTABLESTRING;
        int password_length = strlen(challenge_password);
        ASN1_STRING_set(tmp_os, (const unsigned char *)challenge_password, password_length);
        X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, tmp_os->type, tmp_os->data,
                                password_length);
        ASN1_STRING_free(tmp_os);
    }

    if (0 > X509_REQ_sign(req, (EVP_PKEY *)pk, EVP_sha256()))
    {
        printf("\nError while signing X509_REQ object\n");
        X509_REQ_free(req);
        req = NULL;
        return EST_FALSE;
    }   

    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(mem, req);
    int len = BIO_pending(mem);
    if (len <= 0 || len >= *csr_len) {
        BIO_free(mem);
        return EST_FALSE;
    }
    BIO_read(mem, csr, len);
    csr[len] = '\0';
    *csr_len = len;
    BIO_free(mem);

    return EST_TRUE;
}


/**
 * @brief Generate RSA private key
 *
 * @param key_size: RSA key size
 *
 * @return ESTPrivKey_T
 */
ESTPrivKey_t *generate_rsa_keypair(int key_size)
{
    if (key_size < 1024)
    {
        printf("\nError: key size is too small\n");
        return NULL;
    }
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        goto err;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0)
        goto err;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return (ESTPrivKey_t*) pkey;
err:
    ERR_print_errors_fp(stdout);
    return NULL;
}

/**
 * @brief Generate ECC keypair
 *
 * @param curve_name: ECC curve name
 *
 * @return ESTPrivKey_T
 */
ESTPrivKey_t *generate_ecc_keypair(const char *curve_name)
{
    if (curve_name == NULL)
    {
        printf("\nError: curve name is NULL\n");
        return NULL;
    }
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
        goto err;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    
    int nid = OBJ_txt2nid(curve_name);
    if (nid == NID_undef)
    	goto err;

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)
        goto err;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto err;

    EVP_PKEY_CTX_free(ctx);
    return (ESTPrivKey_t*) pkey;
err:
    ERR_print_errors_fp(stdout);
    return NULL;
}

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

    FILE *fp = fopen(filename, "rt");
    if (!fp)
    {
        printf("\nError: Unable to open file %s\n", filename);
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        printf("\nError while parsing PEM encoded private key from file %s\n", filename);
        fclose(fp);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    fclose(fp);
    return (ESTPrivKey_t *)pkey;
}