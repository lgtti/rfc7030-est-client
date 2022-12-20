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

/* No http body found in response. */
#define EST_ERROR_NOBODY                 0x1

/* Empty response. No certificates found in PKCS7 valid response */
#define EST_ERROR_EMPTY                  0x2

/* Simpleenroll want only one certificate in response. Too many founded. */
#define EST_ERROR_ENROLL_TOOMANY         0x3



/* Structure which contains the /cacert response from the server.*/
typedef struct ESTCaCerts_Info {

  /* chain contains the certificates necessary to construct a chain from
    the certificates issued by the EST CA through to the ta certificiate.*/
  ESTCertificate_t    **chain;

  /* Len relative the the chain field */
  size_t              chain_len;

}ESTCaCerts_Info_t;



/* EST client configuration options, used to build the runtime client.*/
typedef struct ESTClient_Options {

  /* DO NOT USE THIS IN PRODUCTION!
    If set to true the client doesn't verify the Server Certificate status and validity.
    Only useful for testing purposes.*/
  bool_t skip_tls_verify;

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

  /* Interface for the selected HTTP implementation.*/
  ESTHttpInterface_t *httpInterface;

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

/* Request /simpleenroll.
    Requests a new certificate using EST protocol. */
ESTCertificate_t * est_simpleenroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, ESTError_t *err);

/* Request /simplereenroll.
    Requests a renewed certificate using EST protocol. */
ESTCertificate_t * est_simplereenroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, ESTError_t *err);

/* Release inner memory for cacerts response
*/
void est_cacerts_free(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *cacerts);

/* Release inner memory for simpleenroll response
*/
void est_simpleenroll_free(ESTClient_Ctx_t *ctx, ESTCertificate_t *crt);

#endif /* F2508F72_AAF8_4454_A55F_D80E16429572 */
