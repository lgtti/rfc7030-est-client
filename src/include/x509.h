#ifndef A86EFDC9_43D7_430C_8336_B7E51751CF77
#define A86EFDC9_43D7_430C_8336_B7E51751CF77

#include "types.h"
#include "error.h"
#include <stddef.h>


/* Incomplete type for X.509 certificate.
 This type must refer to a host-specific X.509 implementation privided
 by the caller.*/
typedef struct ESTCertificate ESTCertificate_t;

/* Incomplete type for X.509 certificate parsing.
 The caller must implement this function with an input as PEM-formatted byte array of the certificate
 returning the real implementation structure as pointer.*/
typedef ESTCertificate_t * (*EST_x509_certificate_parse_t)(byte_t *pem, int pem_bytes_len, ESTError_t *err);

/* Incomplete type for X.509 certificate check for self signed.
 Output field will be:
 EST_TRUE if self signed
 EST_FALSE is not self signed.*/
typedef bool_t (*EST_x509_certificate_is_self_signed)(ESTCertificate_t *certificate, bool_t *result, ESTError_t *err);

/* Incomplete type for X.509 certificate free.
 The caller must implement this function to free the memory allocated 
 using est_x509_parse_certificate.*/
typedef bool_t (*EST_x509_certificate_free_t)(ESTCertificate_t *output);




/* Incomplete type for X.509 PKCS7.
 This type must refer to a host-specific X.509 implementation privided
 by the caller.*/
typedef struct ESTPKCS7 ESTPKCS7_t;

/* Incomplete type for X.509 PKCS7 parsing.
 The caller must implement this function with an input as PEM-formatted byte array of the pkcs7
 returning the real implementation structure as pointer.*/
typedef ESTPKCS7_t * (*EST_x509_pkcs7_parse_t)(byte_t *p7, int p7_bytes_len, ESTError_t *err);

/* Incomplete type for X.509 certificate free.
 The caller must implement this function to free the memory allocated 
 using est_x509_parse_certificate.*/
typedef bool_t (*EST_x509_pkcs7_free_t)(ESTPKCS7_t *output);

/* Incomplete type for X.509 PKCS7 parsing.
    The caller must implement this function to retrive the inner list of certificates.
    "output" parameter is allocated in this function but deallocated by the EST library.
    Result < 0: error occurred
    Result == 0: no certificates in p7
    Result > 0: len of output.   
 */
typedef size_t (*EST_x509_pkcs7_get_certificates_t)(ESTPKCS7_t *p7, ESTCertificate_t ***output, ESTError_t *err);




typedef struct ESTX509Interface {
    EST_x509_certificate_parse_t certificate_parse;
    EST_x509_certificate_free_t certificate_free;
    EST_x509_certificate_is_self_signed certificate_is_self_signed;
    EST_x509_pkcs7_parse_t pkcs7_parse;
    EST_x509_pkcs7_free_t pkcs7_free;
    EST_x509_pkcs7_get_certificates_t pkcs7_get_certificates;
}ESTX509Interface_t;


#endif /* A86EFDC9_43D7_430C_8336_B7E51751CF77 */
