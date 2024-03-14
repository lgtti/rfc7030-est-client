#include "internal.h"

ESTPKCS7_t * x509_pkcs7_parse(byte_t *b64, int b64_bytes_len, ESTError_t *err) {
    unsigned char *p7der = (unsigned char *)malloc(sizeof(unsigned char) * b64_bytes_len);

    LOG_DEBUG(("Parse openssl pkcs7 len %d\n", b64_bytes_len))

    /* EVP_DecodeBlock don't work with a PEM formatted divided by \n, so we remove all \n characters*/
    byte_t *b64_singleline = (byte_t *)malloc(b64_bytes_len);
    int singleline_idx = 0;
    for(int i = 0; i < b64_bytes_len; i++) {
        if(b64[i] != '\n' && b64[i] != '\r') {
            b64_singleline[singleline_idx++] = b64[i];
        }
    }

    LOG_DEBUG(("Purged openssl pkcs7 len %d\n", singleline_idx))

    // Convert B64 to DER
    int p7der_bytes_len = EVP_DecodeBlock(p7der, (unsigned char *)b64_singleline, singleline_idx);
    if(p7der_bytes_len < 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PREPARE, ERR_get_error(), "Failed to decode pkcs7 pem bytes for BIO");
        oss_print_error();
        free(b64_singleline);
        free(p7der);        
        return NULL;
    }

    free(b64_singleline);

    BIO *mem = BIO_new(BIO_s_mem());

    int written = BIO_write(mem, p7der, p7der_bytes_len);
    if(written < 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PREPARE, ERR_get_error(), "Failed to write pkcs7 pem bytes to BIO");
        oss_print_error();
        BIO_free(mem);
        free(p7der);        
        return NULL;
    }

    PKCS7 *pkcs7 = d2i_PKCS7_bio(mem, NULL);
    if(pkcs7 == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, ERR_get_error(), "Failed to read pkcs7 from BIO");
        oss_print_error();
        BIO_free(mem);
        free(p7der);
        return NULL;
    }

    BIO_free(mem);
    free(p7der);
    return (ESTPKCS7_t *)pkcs7;
}

bool_t x509_pkcs7_free(ESTPKCS7_t *output) {
    assert(output != NULL);
    PKCS7_free((PKCS7 *)output);
    return EST_TRUE;
}

size_t x509_pkcs7_get_certificates(ESTPKCS7_t *p7, ESTCertificate_t ***output, ESTError_t *err) {
    PKCS7 *pkcs7 = (PKCS7 *)p7;

    STACK_OF(X509) *certs = NULL;
    
    // Search for a valid PKCS7 certificate section
    int nid = OBJ_obj2nid(pkcs7->type);
    if(nid == NID_pkcs7_signed) {
        certs = pkcs7->d.sign->cert;
    } else if(nid == NID_pkcs7_signedAndEnveloped) {
        certs = pkcs7->d.signed_and_enveloped->cert;
    }

    if(certs == NULL) {
        LOG_ERROR(("Invalid pkcs7 nid found: %d\n", nid))
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_NOCERTS_SECTION, 0, "Invalid p7 type nid.");
        return -1;
    }

    int numcerts = sk_X509_num(certs);
    if(numcerts == 0) {
        // nocertificates found in this PKCS7
        return 0;
    }

    // Copy all certificates in the response array
    X509 **array = (X509 **)malloc(sizeof(X509 *) * numcerts);

    for(int i = 0; certs && i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        array[i] = X509_dup(cert);
    }

    *output = (ESTCertificate_t **)array;
    return numcerts;
}

ESTCertificate_t * x509_pkcs7_get_first_certificate(ESTPKCS7_t *p7, size_t *len, ESTError_t *err) {
    PKCS7 *pkcs7 = (PKCS7 *)p7;

    STACK_OF(X509) *certs = NULL;

    LOG_DEBUG(("Search for pkcs7 nip certificate content\n"))
    
    // Search for a valid PKCS7 certificate section
    int nid = OBJ_obj2nid(pkcs7->type);
    if(nid == NID_pkcs7_signed) {
        certs = pkcs7->d.sign->cert;
    } else if(nid == NID_pkcs7_signedAndEnveloped) {
        certs = pkcs7->d.signed_and_enveloped->cert;
    }

    if(certs == NULL) {
        LOG_ERROR(("Invalid pkcs7 nid found: %d\n", nid))
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_NOCERTS_SECTION, 0, "Invalid p7 type nid.");
        return NULL;
    }

    LOG_DEBUG(("Extract number of pkcs7 certificates\n"))

    int numcerts = sk_X509_num(certs);
    if(numcerts == 0) {
        // nocertificates found in this PKCS7
        return NULL;
    }

    LOG_DEBUG(("Found pkcs7 %d certificates\n", numcerts))

    X509 *cert = sk_X509_value(certs, 0);
    *len = numcerts;
    return (ESTCertificate_t *)X509_dup(cert);
}

ESTCertificate_t * x509_certificate_parse(byte_t *pem, int pem_bytes_len, ESTError_t *err) {
    BIO *mem = BIO_new(BIO_s_mem());

    int written = BIO_write(mem, pem, pem_bytes_len);
    if(written < 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PREPARE, ERR_get_error(), "Failed to write cert pem bytes to BIO");
        oss_print_error();
        BIO_free(mem);
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    if(cert == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, ERR_get_error(), "Failed to parse x509 certificate from BIO");
        oss_print_error();
        BIO_free(mem);
        return NULL;
    }

    BIO_free(mem);

    return (ESTCertificate_t *)cert;
}

bool_t x509_certificate_free(ESTCertificate_t *cert) {
    assert(cert != NULL);
    X509_free((X509* )cert);
    return EST_TRUE;
}

bool_t x509_certificate_is_self_signed(ESTCertificate_t *certificate, bool_t *result, ESTError_t *err) {
    assert(certificate != NULL);
    assert(result != NULL);

    X509 *cert = (X509 *)certificate;

#if OPENSSL_VERSION_MAJOR > 1
    int ret = X509_self_signed(cert, 1);
#else
    int ret = X509_verify(cert, X509_get_pubkey(cert));
#endif

    *result = ret > 0 ? EST_TRUE : EST_FALSE;

    if(ret < 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ERR_get_error(), "Failed to verify self signed certificate");
        oss_print_error();
        return EST_FALSE;
    }

    return EST_TRUE;
}

bool_t x509_certificate_verify(ESTCertificateStore_t *root, ESTCertificate_t **sub, size_t sub_len, ESTCertificate_t *certificate, bool_t *result, ESTError_t *err) {
    X509_STORE *store = (X509_STORE *)root;
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    if(store_ctx == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ERR_get_error(), "Failed to create openssl cert store ctx");
        oss_print_error();
        return EST_FALSE;
    }

    STACK_OF(X509) *untrusted = sk_X509_new_null();
    if(!untrusted) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ERR_get_error(), "Failed to create openssl cert stack");
        oss_print_error();
        X509_STORE_CTX_free(store_ctx);
        return EST_FALSE;
    }

    // TODO: Can be optimized if "sub" input already is a STACK_OF
    for(int i = 0; i < sub_len; i++) {
        X509 *crt = (X509 *)sub[i];
        sk_X509_push(untrusted, crt);
    }

    if (!X509_STORE_CTX_init(store_ctx, store, NULL, untrusted)) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ERR_get_error(), "Failed to init openssl ctx store");
        oss_print_error();
        sk_X509_free(untrusted);
        X509_STORE_CTX_free(store_ctx);
        return EST_FALSE;
    }

    X509_STORE_CTX_set_cert(store_ctx, (X509 *)certificate);

    if(!X509_verify_cert(store_ctx)) {
        *result = EST_FALSE;
    } else {
        *result = EST_TRUE;
    }

    X509_STORE_CTX_cleanup(store_ctx);
    sk_X509_free(untrusted);
    X509_STORE_CTX_free(store_ctx);
    
    return EST_TRUE;
}

ESTCertificateStore_t * x509_certificate_store_create(ESTError_t *err) {
    X509_STORE *store = X509_STORE_new();
    if(store == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_STORE, ERR_get_error(), "Failed to create openssl cert store");
        oss_print_error();
        return NULL;
    }

    return (ESTCertificateStore_t *)store;
}

void x509_certificate_store_free(ESTCertificateStore_t **store) {
    if(*store) {
        X509_STORE_free((X509_STORE *)*store);
        *store = NULL;
    }
}

bool_t x509_certificate_store_add(ESTCertificateStore_t *store, ESTCertificate_t *certificate, ESTError_t *err) {
    X509_STORE *oss_store = (X509_STORE *)store;
    if(!X509_STORE_add_cert(oss_store, (X509 *)certificate)) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_STORE, ERR_get_error(), "Failed to add openssl cert to store");
        oss_print_error();
        return EST_FALSE;
    }

    return EST_TRUE;
}