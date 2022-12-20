#ifndef A1699372_B3C6_449C_9ECD_BAAAE04D2568
#define A1699372_B3C6_449C_9ECD_BAAAE04D2568

#include "x509.h"
#include "transport_interface.h"
#include "auth.h"

/* Initialize specific implementation of TLS connection. In addition this method MUST make the real connection opening the channel.
    Pay attention to the auth input.
    No auth requested here. This method is used to invoke cacerts endpoint wihtout authentication.
    In addition there is an extra "tls_host" paramater used if the "Host" SNI of the TLS must be different than the connect
    tcp host. If no, please set the same value as "host" parameter. 
    */
typedef bool_t (*EST_tls_initialize)(const char *host, const char *tls_host, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *, ESTError_t *err);

/*  Init a new mTLS connection.
    Same comments as the friend method EST_tls_initialize.
*/
typedef bool_t (*EST_tls_initialize_auth)(const char *host, const char *tls_host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *, ESTError_t *err);


/* Free the allocated memory during TLS_initialize. In addition this method MUST make the real connection opening the channel.
*/
typedef void(*EST_tls_free)(TransportInterface_t *ctx);

typedef struct ESTTLSInterface {
    EST_tls_initialize initialize;
    EST_tls_initialize_auth initialize_auth;
    EST_tls_free free;
}ESTTLSInterface_t;


#endif /* A1699372_B3C6_449C_9ECD_BAAAE04D2568 */
