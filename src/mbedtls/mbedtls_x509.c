#include "internal.h"

ESTPKCS7_t * x509_pkcs7_parse(byte_t *b64, int b64_bytes_len, ESTError_t *err)
{
    if (b64 == NULL || b64_bytes_len == 0 || err == NULL)
    {
        return NULL;
    }
    int ret;
    unsigned char *binary_data = (char *)malloc(b64_bytes_len);
    if (binary_data == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to allocate memory for binary data");
        oss_print_error();
        return NULL;
    }
    size_t binary_len = 0;

    ret = mbedtls_base64_decode(NULL, 0, &binary_len, (const unsigned char *)b64, b64_bytes_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, ret, "Failed to decode base64");
        oss_print_error(ret);
        free(binary_data);
        return NULL;
    }

    ret = mbedtls_base64_decode((unsigned char *)binary_data, binary_len, &binary_len, (const unsigned char *)b64, b64_bytes_len);
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, ret, "Failed to decode base64");
        oss_print_error(ret);
        free(binary_data);
        return NULL;
    }

    mbedtls_pkcs7 *cs7 = (mbedtls_pkcs7 *)malloc(sizeof(mbedtls_pkcs7));
    if (cs7 == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to allocate memory for pkcs7");
        oss_print_error();
        free(binary_data);
        return NULL;
    }
    mbedtls_pkcs7_init(cs7);

    /*
    * NOTICE: This API call may change in the future when mbedTLS implement feature to parse Multiple Certificate
    */
    ret = pkcs7_parse_der(cs7, (char *)binary_data, binary_len);
    if (ret < 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, ret, "Failed to parse pkcs7 from DER");
        oss_print_error(ret);
        mbedtls_pkcs7_free(cs7);
        free(cs7);
        free(binary_data);
        return NULL;
    }
    free(binary_data);

    return (ESTPKCS7_t *)cs7;
}

bool_t x509_pkcs7_free(ESTPKCS7_t *output)
{
    if (output != NULL)
    {
        mbedtls_pkcs7_free((mbedtls_pkcs7 *)output);
        free(output);
    }
    return EST_TRUE;
}

int x509_pkcs7_get_certificates(ESTPKCS7_t *p7, ESTCertificate_t ***output, ESTError_t *err)
{   
    if (p7 == NULL || output == NULL || err == NULL)
    {
        return EST_ERROR;
    }
    mbedtls_pkcs7 *pkcs7 = (mbedtls_pkcs7 *)p7;
    size_t num_cert = pkcs7->private_signed_data.private_no_of_certs;

    *output = (ESTCertificate_t **)malloc(num_cert * sizeof(ESTCertificate_t *));
    if (*output == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to allocate memory for certificates");
        oss_print_error();
        return EST_ERROR;
    }

    mbedtls_x509_crt *crt = &(pkcs7->private_signed_data.private_certs);

    for(int i = 0; i < num_cert; i++) 
    {
        (*output)[i] = (ESTCertificate_t *)malloc(sizeof(mbedtls_x509_crt));
        if ((*output)[i] == NULL)
        {
            est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to allocate memory for certificate");
            oss_print_error();
            return EST_ERROR;
        }
        mbedtls_x509_crt_init((*output)[i]);
        if (mbedtls_x509_crt_parse((*output)[i], crt->raw.p, crt->raw.len) < 0) // Copy the certificate data
        {
            est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to parse certificate");
            oss_print_error();
            return EST_ERROR;
        }

        if (crt->next != NULL)
        {
            crt = crt->next;
        }
    }

    mbedtls_x509_crt_free(crt);
 
    return num_cert;
}

ESTCertificate_t * x509_pkcs7_get_first_certificate(ESTPKCS7_t *p7, size_t *len, ESTError_t *err)
{
    if (p7 == NULL || err == NULL)
    {
        return NULL;
    }
    mbedtls_pkcs7 *pkcs7 = (mbedtls_pkcs7 *)p7;
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (crt == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_PKCS7_PARSE, 0, "Failed to allocate memory for certificate");
        oss_print_error();
        return NULL;
    }

    mbedtls_x509_crt_init(crt);
    mbedtls_x509_crt_parse(crt, pkcs7->private_signed_data.private_certs.raw.p, pkcs7->private_signed_data.private_certs.raw.len); // Copy the certificate data
    *len = 1;
    return (ESTCertificate_t *)crt;
}

ESTCertificate_t * x509_certificate_parse(byte_t *pem, int pem_bytes_len, ESTError_t *err)
{
    if (pem == NULL || pem_bytes_len == 0 || err == NULL)
    {
        return NULL;
    }
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (crt == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, 0, "Failed to allocate memory for x509 certificate");
        oss_print_error();
        return NULL;
    }
    mbedtls_x509_crt_init(crt);

    int ret = mbedtls_x509_crt_parse(crt, (const unsigned char *)pem, pem_bytes_len);
    if(ret != 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, ret, "Failed to parse x509 certificate from PEM");
        oss_print_error();
        mbedtls_x509_crt_free(crt);
        free(crt);
        return NULL;
    }
    
    return (ESTCertificate_t *)crt;
}

bool_t x509_certificate_free(ESTCertificate_t *cert)
{
    if (cert == NULL)
    {
        return EST_FALSE;
    }
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)cert;
    if (crt != NULL)
    {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }
    return EST_TRUE;
}

bool_t x509_certificate_is_self_signed(ESTCertificate_t *certificate, bool_t *result, ESTError_t *err)
{
    int ret;
    if (certificate == NULL || err == NULL)
    {
        return EST_FALSE;
    }

    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)certificate;
    ret = x509_name_cmp(&cert->subject, &cert->issuer);

    if (ret == 0)
    {
        *result = EST_FALSE;
    }
    else if (ret == 1)
    {
        *result = EST_TRUE;
    }
    else
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_SELF_SIGNED, ret, "Failed to compare certificate issuer and subject");
        oss_print_error(ret);
        return EST_FALSE;
    }

    return EST_TRUE;
}

/* CSR typedef - wraps mbedTLS mbedtls_x509_csr structure */
typedef struct {
    mbedtls_x509_csr *csr;
} ESTCSR_mbedtls_impl_t;

/* Forward declarations for helper functions */
int x509_name_cmp( const mbedtls_x509_name *a, const mbedtls_x509_name *b );
int x509_string_cmp( const mbedtls_x509_buf *a, const mbedtls_x509_buf *b );
int x509_memcasecmp( const void *s1, const void *s2, size_t len );

ESTCSR_t * x509_csr_parse(byte_t *pem, int pem_bytes_len, ESTError_t *err) {
    LOG_DEBUG(("Parse CSR, len=%d\n", pem_bytes_len))

    mbedtls_x509_csr *csr = NULL;
    unsigned char *csr_buf = NULL;
    int buf_len = pem_bytes_len;
    
    if (pem == NULL || pem_bytes_len < 1 || err == NULL) {
        LOG_ERROR(("Invalid input to CSR parse\n"));
        return NULL;
    }

    csr = (mbedtls_x509_csr *)malloc(sizeof(mbedtls_x509_csr));
    if (csr == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, 0, "Failed to allocate memory for CSR");
        oss_print_error();
        return NULL;
    }

    mbedtls_x509_csr_init(csr);

    /* Check if input is PEM format (starts with -----BEGIN) */
    if (pem_bytes_len > 10 && memcmp(pem, "-----BEGIN", 10) == 0) {
        LOG_DEBUG(("CSR appears to be PEM format, allocating buffer with null terminator\n"))
        /* For PEM format, mbedtls needs null-terminated string */
        csr_buf = (unsigned char *)malloc(pem_bytes_len + 1);
        if (csr_buf == NULL) {
            est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, 0, "Failed to allocate memory for CSR buffer");
            oss_print_error();
            mbedtls_x509_csr_free(csr);
            free(csr);
            return NULL;
        }
        memcpy(csr_buf, pem, pem_bytes_len);
        csr_buf[pem_bytes_len] = '\0';
        buf_len = pem_bytes_len + 1;
    } else {
        LOG_DEBUG(("CSR appears to be DER format\n"))
        csr_buf = (unsigned char *)pem;
    }

    int ret = mbedtls_x509_csr_parse(csr, csr_buf, buf_len);
    
    /* Free temporary buffer if we allocated one */
    if (csr_buf != (unsigned char *)pem) {
        free(csr_buf);
    }

    if (ret != 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, ret, "Failed to parse CSR from DER/PEM");
        oss_print_error(ret);
        mbedtls_x509_csr_free(csr);
        free(csr);
        return NULL;
    }

    ESTCSR_mbedtls_impl_t *csr_impl = (ESTCSR_mbedtls_impl_t *)malloc(sizeof(ESTCSR_mbedtls_impl_t));
    if (csr_impl == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, 0, "Failed to allocate memory for CSR implementation");
        oss_print_error();
        mbedtls_x509_csr_free(csr);
        free(csr);
        return NULL;
    }
    csr_impl->csr = csr;

    LOG_DEBUG(("CSR parsed successfully\n"))
    return (ESTCSR_t *)csr_impl;
}

bool_t x509_csr_free(ESTCSR_t *csr) {
    if (csr == NULL) {
        return EST_FALSE;
    }
    ESTCSR_mbedtls_impl_t *impl = (ESTCSR_mbedtls_impl_t *)csr;
    if (impl->csr) {
        mbedtls_x509_csr_free(impl->csr);
        free(impl->csr);
    }
    free(impl);
    return EST_TRUE;
}

bool_t x509_verify_cert_csr_pubkey(ESTCertificate_t *certificate, ESTCSR_t *csr, ESTError_t *err) {
    if (err == NULL || certificate == NULL || csr == NULL) {
        LOG_ERROR(("Error parameter is NULL\n"));
        return EST_FALSE;
    }

    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)certificate;
    ESTCSR_mbedtls_impl_t *csr_impl = (ESTCSR_mbedtls_impl_t *)csr;

    if (csr_impl->csr == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_PUBKEY_MISMATCH, 0,
            "CSR implementation pointer is NULL");
        return EST_FALSE;
    }

    LOG_DEBUG(("Comparing certificate and CSR public keys\n"))

    /* Check if key types match */
    if (mbedtls_pk_get_type(&cert->pk) != mbedtls_pk_get_type(&csr_impl->csr->pk)) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_PUBKEY_MISMATCH, 0, 
            "Certificate and CSR have different key types");
        return EST_FALSE;
    }

    /* Serialize both public keys to DER format and compare */
    unsigned char cert_pubkey_der[1024] = {0};
    unsigned char csr_pubkey_der[1024] = {0};
    
    int cert_der_len = mbedtls_pk_write_pubkey_der(&cert->pk, cert_pubkey_der, sizeof(cert_pubkey_der));
    if (cert_der_len < 0) {
        LOG_ERROR(("mbedTLS pk_write error: -0x%04X\n", -cert_der_len));
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_PUBKEY_MISMATCH, 0, "Failed to serialize certificate public key");
        return EST_FALSE;
    }

    int csr_der_len = mbedtls_pk_write_pubkey_der(&csr_impl->csr->pk, csr_pubkey_der, sizeof(csr_pubkey_der));
    if (csr_der_len < 0) {
        LOG_ERROR(("mbedTLS pk_write error: -0x%04X\n", -csr_der_len));
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_PUBKEY_MISMATCH, 0, "Failed to serialize CSR public key");
        return EST_FALSE;
    }

    /* Compare the DER representations */
    /* Note: mbedtls_pk_write_pubkey_der writes to END of buffer, so calculate correct offsets */
    unsigned char *cert_der_start = &cert_pubkey_der[sizeof(cert_pubkey_der) - cert_der_len];
    unsigned char *csr_der_start = &csr_pubkey_der[sizeof(csr_pubkey_der) - csr_der_len];
    
    if (cert_der_len != csr_der_len || memcmp(cert_der_start, csr_der_start, cert_der_len) != 0) 
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_PUBKEY_MISMATCH, 0, 
            "Failed to compare public keys between certificate and CSR");
        return EST_FALSE;
    }

    LOG_DEBUG(("Public keys match\n"))
    return EST_TRUE;
}

bool_t x509_verify_cert_csr_subject(ESTCertificate_t *certificate, ESTCSR_t *csr, ESTError_t *err) {
    if (err == NULL || certificate == NULL || csr == NULL) {
        LOG_ERROR(("Error parameter is NULL\n"));
        return EST_FALSE;
    }

    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)certificate;
    ESTCSR_mbedtls_impl_t *csr_impl = (ESTCSR_mbedtls_impl_t *)csr;

    LOG_DEBUG(("Comparing certificate and CSR subjects\n"))

    /* Compare certificate subject with CSR subject */
    int cmp_result = x509_name_cmp(&cert->subject, &csr_impl->csr->subject);
    
    if (cmp_result != EST_TRUE) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_SUBJECT_MISMATCH, 0, 
            "Certificate and CSR subjects do not match");
        return EST_FALSE;
    }

    LOG_DEBUG(("Certificate and CSR subjects match\n"))
    return EST_TRUE;
}

/*  
 *  This function is derived from Mbed TLS.  
 *  Copyright The Mbed TLS Contributors  
 *  SPDX-License-Identifier: Apache-2.0
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");  
 *  you may not use this file except in compliance with the License.  
 *  You may obtain a copy of the License at  
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0  
 *  
 *  Unless required by applicable law or agreed to in writing, software  
 *  distributed under the License is distributed on an "AS IS" BASIS,  
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
 *  See the License for the specific language governing permissions and  
 *  limitations under the License.  
 */  
int x509_name_cmp( const mbedtls_x509_name *a, const mbedtls_x509_name *b )
{
    if (a == NULL || b == NULL)
    {
        return -1;
    }
    /* Avoid recursion, it might not be optimised by the compiler */
    while( a != NULL || b != NULL )
    {
        if( a == NULL || b == NULL )
            return( -1 );

        /* type */
        if( a->oid.tag != b->oid.tag ||
            a->oid.len != b->oid.len ||
            memcmp( a->oid.p, b->oid.p, b->oid.len ) != 0 )
        {
            return( EST_FALSE );
        }

        /* value */
        if( x509_string_cmp( &a->val, &b->val ) != 0 )
            return( EST_FALSE );

        /* structure of the list of sets */
        if( a->private_next_merged != b->private_next_merged )
            return( EST_FALSE );

        a = a->next;
        b = b->next;
    }

    /* a == NULL == b */
    return EST_TRUE;
}

/*  
 *  This function is derived from Mbed TLS.  
 *  Copyright The Mbed TLS Contributors  
 *  SPDX-License-Identifier: Apache-2.0
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");  
 *  you may not use this file except in compliance with the License.  
 *  You may obtain a copy of the License at  
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0  
 *  
 *  Unless required by applicable law or agreed to in writing, software  
 *  distributed under the License is distributed on an "AS IS" BASIS,  
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
 *  See the License for the specific language governing permissions and  
 *  limitations under the License.  
 */  
int x509_string_cmp( const mbedtls_x509_buf *a, const mbedtls_x509_buf *b )
{
    if (a == NULL || b == NULL)
    {
        return -1;
    }
    
    if( a->tag == b->tag &&
        a->len == b->len &&
        memcmp( a->p, b->p, b->len ) == 0 )
    {
        return( 0 );
    }

    if( ( a->tag == MBEDTLS_ASN1_UTF8_STRING || a->tag == MBEDTLS_ASN1_PRINTABLE_STRING ) &&
        ( b->tag == MBEDTLS_ASN1_UTF8_STRING || b->tag == MBEDTLS_ASN1_PRINTABLE_STRING ) &&
        a->len == b->len &&
        x509_memcasecmp( a->p, b->p, b->len ) == 0 )
    {
        return( 0 );
    }

    return( -1 );
}

/*  
 *  This function is derived from Mbed TLS.  
 *  Copyright The Mbed TLS Contributors  
 *  SPDX-License-Identifier: Apache-2.0
 *  
 *  Licensed under the Apache License, Version 2.0 (the "License");  
 *  you may not use this file except in compliance with the License.  
 *  You may obtain a copy of the License at  
 *  
 *      http://www.apache.org/licenses/LICENSE-2.0  
 *  
 *  Unless required by applicable law or agreed to in writing, software  
 *  distributed under the License is distributed on an "AS IS" BASIS,  
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
 *  See the License for the specific language governing permissions and  
 *  limitations under the License.  
 */  
int x509_memcasecmp( const void *s1, const void *s2, size_t len )
{
    if (s1 == NULL || s2 == NULL)
    {
        return -1;
    }
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    for( i = 0; i < len; i++ )
    {
        diff = n1[i] ^ n2[i];

        if( diff == 0 )
            continue;

        if( diff == 32 &&
            ( ( n1[i] >= 'a' && n1[i] <= 'z' ) ||
              ( n1[i] >= 'A' && n1[i] <= 'Z' ) ) )
        {
            continue;
        }

        return( -1 );
    }

    return( 0 );
}

bool_t x509_certificate_verify(ESTCertificateStore_t *root, ESTCertificate_t **chain, size_t chain_len, ESTCertificate_t *certificate, bool_t *result, ESTError_t *err)
{
    /*
    E.g.: Chain of 4 certificates:
    intermediateC -> intermediateB -> intermediateA -> root
        We need to verify base in order:
            1. intermediateC -> intermediateB
            2. intermediateB -> intermediateA
            3. intermediateA -> root
    */
    uint32_t flags;
    int ret;

    // Keep track of Intermediate Certificate in chain
    static int index = 1;
    if (root == NULL || chain_len == 0 || certificate == NULL || chain == NULL || err == NULL)
    {
        return EST_FALSE;
    }
    mbedtls_x509_crt *root_crt = (mbedtls_x509_crt *)root;
    mbedtls_x509_crt *cert = (mbedtls_x509_crt *)certificate;

    mbedtls_x509_crt *intermediate_certs = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (intermediate_certs == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, 0, "Failed to allocate memory for intermediate certificates");
        oss_print_error();
        return EST_FALSE;
    }
    mbedtls_x509_crt_init(intermediate_certs);

    // if last certificate in chain is the root certificate, verify the certificate against the root certificate
    if (index == chain_len)
    {
        ret = mbedtls_x509_crt_verify(cert, root, NULL, NULL, &flags, NULL, NULL);
    }
    else // if not, verify the certificate against the intermediate certificate
    {
        if (index >= chain_len)
        {
            est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, 0, "Invalid index for certificate chain");
            mbedtls_x509_crt_free(intermediate_certs);
            free(intermediate_certs);
            return EST_FALSE;
        }

        mbedtls_x509_crt *crt = (mbedtls_x509_crt *)chain[index];
        ret = mbedtls_x509_crt_parse(intermediate_certs, crt->raw.p, crt->raw.len);
        if (ret < 0)
        {
            est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ret, "Failed to parse intermediate certificate");
            oss_print_error(ret);
            mbedtls_x509_crt_free(intermediate_certs);
            free(intermediate_certs);
            return EST_FALSE;
        }

        ret = mbedtls_x509_crt_verify(cert, intermediate_certs, NULL, NULL, &flags, NULL, NULL);
        index += 1;
    }
    
    if(ret != 0) {
        *result = EST_FALSE;
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_VERIFY, ret, "Failed to verify certificate");
        oss_print_error(ret);
    } else {
        *result = EST_TRUE;
    }

    mbedtls_x509_crt_free(intermediate_certs);
    free(intermediate_certs);
    return EST_TRUE;
}

ESTCertificateStore_t * x509_certificate_store_create(ESTError_t *err)
{
    if (err == NULL)
    {
        return NULL;
    }
    mbedtls_x509_crt *store = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if(store == NULL) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_STORE, 0, "Failed to allocate memory for cert store");
        oss_print_error();
        return NULL;
    }
    mbedtls_x509_crt_init(store);

    return (ESTCertificateStore_t *)store;
}

void x509_certificate_store_free(ESTCertificateStore_t **store)
{
    if (*store != NULL)
    {
        mbedtls_x509_crt_free((mbedtls_x509_crt *)*store);
        free(*store);
        *store = NULL;
    }
}

bool_t x509_certificate_store_add(ESTCertificateStore_t *store, ESTCertificate_t *certificate, ESTError_t *err)
{
    if (store == NULL || certificate == NULL)
    {
        return EST_FALSE;
    }
    mbedtls_x509_crt *crt_store = (mbedtls_x509_crt *)store;
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)certificate;

    // if store never had a certificate, add the first certificate
    if (crt_store->raw.p == 0)
    {
        mbedtls_x509_crt_parse(crt_store, crt->raw.p, crt->raw.len);
    }
    else
    {
        // if store already has a certificate, add the new certificate to the end of the list
        mbedtls_x509_crt *current = crt_store;
        while (current->next != NULL)
        {
            current = current->next;
        }
        mbedtls_x509_crt_parse(current->next, crt->raw.p, crt->raw.len);
    }

    return EST_TRUE;
}