#include "rfc7030.h"

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>

void load_legacy_module();
void free_legacy_module();
char *oss_err_as_string (void);
void oss_print_error();
void oss_load_implicit_ta(const char *chain_pem, ESTClient_Options_t *opts);
void oss_free_implicit_ta(ESTClient_Options_t *opts);
int oss_crt2pem_noterminator(X509 *crt, char *pem, size_t pem_len);

#define EST_ERROR_TLS_SSL_CTX                           0x1
#define EST_ERROR_TLS_STORE_CA_CERT                     0x2
#define EST_ERROR_TLS_CONNECT                           0x3
#define EST_ERROR_TLS_GET_TUNNEL_REF                    0x4
#define EST_ERROR_TLS_START_HANDSHAKE                   0x5
#define EST_ERROR_TLS_SERVERCERT_MISSING                0x6
#define EST_ERROR_TLS_SERVERCERT_INVALID                0x7

bool_t tls_unique(TransportInterface_t  *tint, char *output, size_t *len, ESTError_t *err);
int32_t tls_recv( NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv );
int32_t tls_send( NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend );
bool_t tls_init(const char *host, const char *tls_host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *tint, ESTError_t *err);
void tls_free(TransportInterface_t *ctx);

#define EST_ERROR_X509_PKCS7_PREPARE            0x1
#define EST_ERROR_X509_PKCS7_PARSE              0x2
#define EST_ERROR_X509_PKCS7_NOCERTS_SECTION    0x3
#define EST_ERROR_X509_CERT_PREPARE             0x4
#define EST_ERROR_X509_CERT_PARSE               0x5
#define EST_ERROR_X509_CERT_VERIFY              0x6
#define EST_ERROR_X509_CERT_STORE               0x7
#define EST_ERROR_X509_P12                      0x8
#define EST_ERROR_X509_B64                      0x9

ESTPKCS7_t * x509_pkcs7_parse(byte_t *b64, int b64_bytes_len, ESTError_t *err);
bool_t x509_pkcs7_free(ESTPKCS7_t *output);
size_t x509_pkcs7_get_certificates(ESTPKCS7_t *p7, ESTCertificate_t ***output, ESTError_t *err);
ESTCertificate_t * x509_pkcs7_get_first_certificate(ESTPKCS7_t *p7, size_t *len, ESTError_t *err);
ESTCertificate_t * x509_certificate_parse(byte_t *pem, int pem_bytes_len, ESTError_t *err);
bool_t x509_certificate_free(ESTCertificate_t *cert);
bool_t x509_certificate_is_self_signed(ESTCertificate_t *certificate, bool_t *result, ESTError_t *err);
bool_t x509_certificate_verify(ESTCertificateStore_t *root, ESTCertificate_t **sub, size_t sub_len, ESTCertificate_t *certificate, bool_t *result, ESTError_t *err);
ESTCertificateStore_t * x509_certificate_store_create(ESTError_t *err);
void x509_certificate_store_free(ESTCertificateStore_t **store);
bool_t x509_certificate_store_add(ESTCertificateStore_t *store, ESTCertificate_t *certificate, ESTError_t *err);