#include "internal.h"

ESTCertificate_t * pf2crt(const char *name) {
    FILE *pf = fopen(name, "rt");
    return (ESTCertificate_t *)PEM_read_X509(pf, NULL, NULL, NULL);
}

ESTCertificate_t * pem2crt(const char *pem) {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, pem);
    return (ESTCertificate_t *)PEM_read_bio_X509(bio, NULL, NULL, NULL);
}

bool_t crt_equals(ESTCertificate_t *received, ESTCertificate_t *expected) {
    int ret = X509_cmp((X509 *)received, (X509 *)expected);
    return ret == 0 ? EST_TRUE : EST_FALSE;
}

bool_t is_issuer(ESTCertificate_t *issuer, ESTCertificate_t *crt) {
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
    FILE *pf = fopen(pkeyfilename, "rt");
    EVP_PKEY *pk = PEM_read_PrivateKey(pf, NULL, NULL, NULL);

    X509_REQ *req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pk);

    X509_NAME *x509Name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC, (const unsigned char *)"IT", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC, (const unsigned char *)"Rfc7030", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "OU", MBSTRING_ASC, (const unsigned char *)"EstClient", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC, (const unsigned char *)"IntegrationTest", -1, -1, 0);
    X509_REQ_set_subject_name(req, x509Name);
    X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, MBSTRING_ASC, (const unsigned char *)tlsunique, -1);

    X509_REQ_sign(req, pk, EVP_sha256());

    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(mem, req);
    *csr_len = BIO_read(mem, csr, *csr_len);
    BIO_free(mem);

    return EST_TRUE;
}