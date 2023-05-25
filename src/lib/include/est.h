#ifndef F2508F72_AAF8_4454_A55F_D80E16429572
#define F2508F72_AAF8_4454_A55F_D80E16429572

#include "types.h"
#include "x509.h"
#include "error.h"
#include "config.h"
#include "auth.h"
#include "transport_interface.h"
#include "tls.h"
#include "http.h"


#define EST_LIB_VERSION  "RFC7030-ESTClient-1.0.0"

/* No http body found in response. */
#define EST_ERROR_NOBODY                 0x1

/* Empty response. No certificates found in PKCS7 valid response */
#define EST_ERROR_EMPTY                  0x2

/* Simpleenroll want only one certificate in response. Too many founded. */
#define EST_ERROR_ENROLL_TOOMANY         0x3

/* Cacerts want only HTTP 200 OK status code. */
#define EST_ERROR_CACERTS_HTTP_KO        0x4

/* Error used if headers response are not valid. */
#define EST_ERROR_CACERTS_BADREQUEST     0x5

/* Error used if one cacert certificate is not valid. */
#define EST_ERROR_CACERTS_INVALID        0x6

/* Error used if server requires retry. Native code is the retry delay. */
#define EST_ERROR_ENROLL_RETRY           0x7

/* Error used if server response has invalid headers. */
#define EST_HTTP_ERROR_BAD_HEADERS       0x8

/* Error used if the client cannot parse server http response. */
#define EST_ERROR_HTTP_RESP_PARSE        0x9

/* Error used if the server http response is partial. */
#define EST_ERROR_HTTP_RESP_PARSE_INC    0x10

/* Error used if the client fails during receive from socket . */
#define EST_ERROR_HTTP_RECV              0x11

/* Error used if the client fails during send to socket . */
#define EST_ERROR_HTTP_SEND              0x12


/* Max len of http paths for EST */
#define EST_HTTP_PATH_LEN 32

/* Structure which contains the /cacert response from the server.*/
typedef struct ESTCaCerts_Info {

  /* chain contains the certificates necessary to construct a chain from
    the certificates issued by the EST CA through to the ta certificiate.*/
  ESTCertificate_t    **chain;

  /* Len relative the the chain field */
  size_t              chain_len;

}ESTCaCerts_Info_t;

/* Inform the caller with the value sof the generated tls-unique */
typedef void (*est_publish_tls_unique)(const char *value, size_t len);

/* Users of this library must implement this callback to provide a valid csr */
typedef bool_t (*est_get_csr_t)(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err);


/* EST client configuration options, used to build the runtime client.*/
typedef struct ESTClient_Options {

  /* DO NOT USE THIS IN PRODUCTION!
    If set to true the client doesn't verify the Server Certificate status and validity.
    Only useful for testing purposes.*/
  bool_t skip_tls_verify;

  /* Retrieve TLS unique information from TLS channel and publishe the value to the caller. */
  bool_t use_pop;

  /* Trust anchor chain used to verify the EST server certificate. */
  ESTCertificate_t **chain;

  /* Len relative the the chain field. */
  size_t              chain_len;

  /* 3.2.2.  HTTP URIs for Control
  https://www.example.com/.well-known/est/cacerts
  https://www.example.com/.well-known/est/arbitraryLabel1/cacerts
  https://www.example.com/.well-known/est/arbitraryLabel2/cacerts
    
    NOTE: '\0' terminator defines the effective len of the label field. 
    If len == 0, no label is used.*/
  char label[EST_CLIENT_LABEL_LEN];

  /* Interface for the native machine encryption implementation (x509, pkcs7..).*/
  ESTX509Interface_t *x509Interface;

  /* Interface for the native machine network implementation (TLS).*/
  ESTTLSInterface_t *tlsInterface;

  /* Implementation of callback to compose the csr*/
  est_get_csr_t get_csr;

}ESTClient_Options_t;



typedef struct ESTClient_Ctx ESTClient_Ctx_t;

/* Initialized a new ESTClient instance.
 If return is NULL, check err structure to identify the error.
 
 NOTE: this method makes a memcpy of the ESTClient_Options_t input structure, so
 all the pointer fields of the structure instance must be allocated in the heap. */
ESTClient_Ctx_t * est_initialize(const ESTClient_Options_t *opts, ESTError_t *err);

/* Clear all the allocated memory for the specified context.*/
void est_free(ESTClient_Ctx_t **ctx);

/* Open a TLS connection with the requested EST Server.*/
bool_t est_connect(ESTClient_Ctx_t *ctx, const char *host, int port, const ESTAuthData_t *auth, ESTError_t *err);

/* Request /cacert.
    This method returns the server list of CA certificates used by the client to 
    verify the server in al other call but could be used by the device to trust 
    all others TLS connections.
   */
bool_t est_cacerts(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *output, ESTError_t *err);

/* Release inner memory for cacerts response
*/
void est_cacerts_free(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *cacerts);

/* Request /simpleenroll or /simplereenroll */
ESTCertificate_t * est_enroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, bool_t renew, ESTError_t *err);

/* Release inner memory for simpleenroll response
*/
void est_enroll_free(ESTClient_Ctx_t *ctx, ESTCertificate_t *crt);



typedef struct ESTClientEnroll_Ctx {
  ESTCaCerts_Info_t cacerts;
  ESTCertificate_t *enrolled;
  ESTClient_Ctx_t *ctx;
}ESTClientEnroll_Ctx_t;

typedef struct ESTClientCacerts_Ctx {
  ESTCaCerts_Info_t cacerts;
  ESTClient_Ctx_t *ctx;
}ESTClientCacerts_Ctx_t;

bool_t est_client_cacerts(const ESTClient_Options_t *opts, const char *host, int port, ESTClientCacerts_Ctx_t *output, ESTError_t *err);
void est_client_cacerts_free(ESTClientCacerts_Ctx_t *cacerts_ctx);
bool_t est_client_simpleenroll(const ESTClient_Options_t *opts, 
    const char *host, 
    int port, 
    ESTAuthData_t *auth,
    void *csr_ctx, 
    ESTClientEnroll_Ctx_t *output,
    ESTError_t *err);
bool_t est_client_simplereenroll(const ESTClient_Options_t *opts, 
    const char *host, 
    int port, 
    ESTAuthData_t *auth,
    void *csr_ctx, 
    ESTClientEnroll_Ctx_t *output,
    ESTError_t *err);
void est_client_enroll_free(ESTClientEnroll_Ctx_t *enroll_ctx);

#endif /* F2508F72_AAF8_4454_A55F_D80E16429572 */
