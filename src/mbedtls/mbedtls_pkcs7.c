/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 * 
 *  Modifications provided by Schneider Electric in 2024. Description of the changes:
 *      - Disable DER parser of DigestAlgorithmIdentifiers
 *      - Add support for parsing multiple certificates  
 */

#include "internal.h"

int pkcs7_parse_der(mbedtls_pkcs7 *pkcs7,  char *buf, const size_t buflen)
{
    unsigned char *p;
    unsigned char *end;
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (pkcs7 == NULL || buf == NULL)
    {
        return (MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA);
    }

    /* make an internal copy of the buffer for parsing */
    pkcs7->private_raw.p = p = (unsigned char *)malloc(buflen);
    if (pkcs7->private_raw.p == NULL)
    {
        return (MBEDTLS_ERR_PKCS7_ALLOC_FAILED);
    }
    memset(pkcs7->private_raw.p, 1, buflen);

    memcpy(p, buf, buflen);
    pkcs7->private_raw.len = buflen;
    end = p + buflen;

    // *contentInfo : SEQUENCE
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE )) != 0)
    {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if ((size_t) (end - p) != len)
    {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    // *	contentType : ObjectIdentifier  {data|signedData|envelopedData|signedAndEnvelopedData|digestedData|encryptedData}
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID)) != 0)
    {
        if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) 
        {
            return MBEDTLS_ERR_X509_INVALID_FORMAT;
        }
        p = pkcs7->private_raw.p;
        len = buflen;
        goto try_data;
    }

    p += len;
    
    // *	content[optional] : SEQUENCE
    // Get next content_len
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED| MBEDTLS_ASN1_CONTEXT_SPECIFIC)) !=  0)
    {
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    } 
    else if ((size_t) (end - p) != len)
    {
        return MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO;
    }
    
    if (p + len != end)
    {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

try_data:
    /**
     * SignedData ::= SEQUENCE {
     *      version Version,
     *      digestAlgorithms DigestAlgorithmIdentifiers,
     *      contentInfo ContentInfo,
     *      certificates
     *              [0] IMPLICIT ExtendedCertificatesAndCertificates
     *                  OPTIONAL,
     *      crls
     *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
     *      signerInfos SignerInfos }
     */

    ret = pkcs7_get_signed_data(p, len, &pkcs7->private_signed_data);
    if (ret != 0)
    {
        return ret;
    }

    return MBEDTLS_PKCS7_SIGNED_DATA;
}

int pkcs7_get_signed_data(unsigned char *buf, size_t buflen, mbedtls_pkcs7_signed_data *signed_data)
{
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    unsigned char *end_content_info = NULL;
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0)
    {
        return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
    }

    if (p + len != end)
    {
        return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
    }

    /* Get version of signed data */
    ret = pkcs7_get_version(&p, end, &signed_data->private_version);
    if (ret != 0) {
        return ret;
    }

    /* Get digest algorithm */
    ret = pkcs7_get_digest_algorithm_set(&p, end,
                                         &signed_data->private_digest_alg_identifiers);
    if (ret != 0) {
        return ret;
    }

    // get content info
    mbedtls_pkcs7_buf content_type;
    memset(&content_type, 0, sizeof(content_type));
    ret = pkcs7_get_content_info_type(&p, end, &end_content_info, &content_type);
    if (ret != 0) {
        return ret;
    }

    if (p != end_content_info) {
        /* Determine if valid content is present */
        ret = mbedtls_asn1_get_tag(&p,
                                   end_content_info,
                                   &len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
        }
        p += len;
        if (p != end_content_info) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
        }
        /* Valid content is present - this is not supported */
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }

    /* Look for certificates, there may or may not be any */
    mbedtls_x509_crt_init(&signed_data->private_certs);
    ret = pkcs7_get_certificates(&p, end, &signed_data->private_certs);
    if (ret < 0) {
        return ret;
    }

    signed_data->private_no_of_certs = ret;

    /*
     * Currently CRLs are not supported. If CRL exist, the parsing will fail
     * at next step of getting signers info and return error as invalid
     * signer info.
     */

    signed_data->private_no_of_crls = 0;

    // NOTE: openxpki pkcs7 response strucutre, does not contain signers info
    // Check if end of buffer is reached
    if (*p == *end)
    {
        return 0;
    }

    /* Get signers info */
    ret = pkcs7_get_signers_info_set(&p,
                                     end,
                                     &signed_data->private_signers,
                                     &signed_data->private_digest_alg_identifiers);
    if (ret < 0) {
        oss_print_error(ret);
        return ret;
    }

    signed_data->private_no_of_signers = ret;

    /* Don't permit trailing data */
    if (p != end) {
        return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
    }

    return 0;
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version(unsigned char **p, unsigned char *end, int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_int(p, end, ver);
    if (ret != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_VERSION, ret);
    }

    /* If version != 1, return invalid version */
    if (*ver != MBEDTLS_PKCS7_SUPPORTED_VERSION) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_VERSION;
    }

    return ret;
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set(unsigned char **p,
                                          unsigned char *end,
                                          mbedtls_x509_buf *alg)
{
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SET);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    end = *p + len;

    /*
        NOTE: pkcs7 from OpenXPKI EST Server Does not have DigestAlgorithmIdentifiers
        So, we are not parsing it.
    */

    // ret = mbedtls_asn1_get_alg_null(p, end, alg);
    // if (ret != 0) {
    //     return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    // }

    /** For now, it assumes there is only one digest algorithm specified **/
    if (*p != end) {
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type(unsigned char **p, unsigned char *end,
                                       unsigned char **seq_end,
                                       mbedtls_pkcs7_buf *pkcs7)
{
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *start = *p;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        *p = start;
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
    }
    *seq_end = *p + len;
    ret = mbedtls_asn1_get_tag(p, *seq_end, &len, MBEDTLS_ASN1_OID);
    if (ret != 0) {
        *p = start;
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
    }

    pkcs7->tag = MBEDTLS_ASN1_OID;
    pkcs7->len = len;
    pkcs7->p = *p;
    *p += len;

    return ret;
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 * Return number of certificates added to the signed data,
 * 0 or higher is valid.
 * Return negative error code for failure.
 **/
static int pkcs7_get_certificates(unsigned char **p, unsigned char *end,
                                  mbedtls_x509_crt *certs)
{
    /*
        NOTE: pkcs7_get_certificates mbedTLS cannot parse multiple certificates/chain of certificates
        We implemented our own function to parse multiple certificates from CA server response
    */

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t certSetLen = 0;
    size_t certLen = 0;
    size_t num_cert = 1;
    unsigned char *end_set, *end_cert, *start;

    // Check if there are any certificates
    ret = mbedtls_asn1_get_tag(p, end, &certSetLen, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return 0;
    }
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
    }
    // Set Pointers to start of certificate
    start = *p;
    // Set pointer to end of certificate set
    end_set = *p + certSetLen;

    // Parse first certificate length
    ret = mbedtls_asn1_get_tag(p, end_set, &certLen, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT, ret);
    }

    // Pointer to end of first certificate
    end_cert = *p + certLen;

    
    // parse first certificate (x509 struct, starting pointer of first certificate, length of first certificate + offset)
    if ((ret = mbedtls_x509_crt_parse_der(certs, start, certLen + 4)) < 0) {
        oss_print_error(ret);
        return MBEDTLS_ERR_PKCS7_INVALID_CERT;
    }
    // starting point of next certificate
    start = *p + certLen;

    mbedtls_x509_crt *temp_certificate = certs;
    // Parse others certificates if exist
    while (end_cert != end_set) {
        // get length of next certificate (end_cert pointer of prev cert, end of set, length of set)
        ret = mbedtls_asn1_get_tag(&end_cert, end_set, &certLen, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            oss_print_error(ret);
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT, ret);
        }

        // update pointer of second cert
        end_cert += certLen;

        // Allocate memory for next certificate
        mbedtls_x509_crt *new_cert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
        if (new_cert == NULL) {
            return MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        }
        mbedtls_x509_crt_init(new_cert);
        
        // Parse next certificate (x509 struct, starting pointer of second certificate, length of second certificate + offset)
        if ((ret = mbedtls_x509_crt_parse_der(new_cert, start, certLen + 4)) < 0) {
            oss_print_error(ret);
            free(new_cert);
            return MBEDTLS_ERR_PKCS7_INVALID_CERT;
        }
        num_cert++;

        while (temp_certificate->next != NULL) {
            temp_certificate = temp_certificate->next;
        }
        temp_certificate->next = new_cert;
        
        // update starting point of next certificate (by assignment pointer of end of previous certificate)
        start = end_cert;
    }

    // update pointer to end of certificate set
    *p = end_set + 2;
    
    return num_cert;
}

/**
 * SignerInfos ::= SET of SignerInfo
 * Return number of signers added to the signed data,
 * 0 or higher is valid.
 * Return negative error code for failure.
 **/
static int pkcs7_get_signers_info_set(unsigned char **p, unsigned char *end,
                                      mbedtls_pkcs7_signer_info *signers_set,
                                      mbedtls_x509_buf *digest_alg)
{
    unsigned char *end_set;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int count = 0;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SET);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    }

    /* Detect zero signers */
    if (len == 0) {
        return 0;
    }

    end_set = *p + len;

    ret = pkcs7_get_signer_info(p, end_set, signers_set, digest_alg);
    if (ret != 0) {
        return ret;
    }
    count++;

    mbedtls_pkcs7_signer_info *prev = signers_set;
    while (*p != end_set) {
        mbedtls_pkcs7_signer_info *signer =
            mbedtls_calloc(1, sizeof(mbedtls_pkcs7_signer_info));
        if (!signer) {
            ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
            goto cleanup;
        }

        ret = pkcs7_get_signer_info(p, end_set, signer, digest_alg);
        if (ret != 0) {
            mbedtls_free(signer);
            goto cleanup;
        }
        prev->private_next = signer;
        prev = signer;
        count++;
    }

    return count;

cleanup:
    pkcs7_free_signer_info(signers_set);
    mbedtls_pkcs7_signer_info *signer = signers_set->private_next;
    while (signer != NULL) {
        prev = signer;
        signer = signer->private_next;
        pkcs7_free_signer_info(prev);
        mbedtls_free(prev);
    }
    signers_set->private_next = NULL;
    return ret;
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 * Returns 0 if the signerInfo is valid.
 * Return negative error code for failure.
 * Structure must not contain vales for authenticatedAttributes
 * and unauthenticatedAttributes.
 **/
static int pkcs7_get_signer_info(unsigned char **p, unsigned char *end,
                                 mbedtls_pkcs7_signer_info *signer,
                                 mbedtls_x509_buf *alg)
{
    unsigned char *end_signer, *end_issuer_and_sn;
    int asn1_ret = 0, ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    asn1_ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                    | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    end_signer = *p + len;

    ret = pkcs7_get_version(p, end_signer, &signer->private_version);
    if (ret != 0) {
        goto out;
    }

    asn1_ret = mbedtls_asn1_get_tag(p, end_signer, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    end_issuer_and_sn = *p + len;
    /* Parsing IssuerAndSerialNumber */
    signer->private_issuer_raw.p = *p;

    asn1_ret = mbedtls_asn1_get_tag(p, end_issuer_and_sn, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    ret  = mbedtls_x509_get_name(p, *p + len, &signer->private_issuer);
    if (ret != 0) {
        goto out;
    }

    signer->private_issuer_raw.len =  (size_t) (*p - signer->private_issuer_raw.p);

    ret = mbedtls_x509_get_serial(p, end_issuer_and_sn, &signer->private_serial);
    if (ret != 0) {
        goto out;
    }

    /* ensure no extra or missing bytes */
    if (*p != end_issuer_and_sn) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        goto out;
    }

    ret = pkcs7_get_digest_algorithm(p, end_signer, &signer->private_sig_alg_identifier);
    if (ret != 0) {
        goto out;
    }

    /* Check that the digest algorithm used matches the one provided earlier */
    if (signer->private_sig_alg_identifier.tag != alg->tag ||
        signer->private_sig_alg_identifier.len != alg->len ||
        memcmp(signer->private_sig_alg_identifier.p, alg->p, alg->len) != 0) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        goto out;
    }

    /* Assume authenticatedAttributes is nonexistent */
    ret = pkcs7_get_digest_algorithm(p, end_signer, &signer->private_sig_alg_identifier);
    if (ret != 0) {
        goto out;
    }

    ret = pkcs7_get_signature(p, end_signer, &signer->private_sig);
    if (ret != 0) {
        goto out;
    }

    /* Do not permit any unauthenticated attributes */
    if (*p != end_signer) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
    }

out:
    if (asn1_ret != 0 || ret != 0) {
        pkcs7_free_signer_info(signer);
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO,
                                asn1_ret);
    }

    return ret;
}

static void pkcs7_free_signer_info(mbedtls_pkcs7_signer_info *signer)
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    if (signer == NULL) {
        return;
    }

    name_cur = signer->private_issuer.next;
    while (name_cur != NULL) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_free(name_prv);
    }
    signer->private_issuer.next = NULL;
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature(unsigned char **p, unsigned char *end, mbedtls_pkcs7_buf *signature)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        return ret;
    }

    signature->tag = MBEDTLS_ASN1_OCTET_STRING;
    signature->len = len;
    signature->p = *p;

    *p = *p + len;

    return 0;
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm(unsigned char **p, unsigned char *end, mbedtls_x509_buf *alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg_null(p, end, alg)) != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    return ret;
}