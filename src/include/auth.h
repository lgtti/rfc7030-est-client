#ifndef D5F3F934_DFB4_4190_89B8_1926BFD61AE5
#define D5F3F934_DFB4_4190_89B8_1926BFD61AE5

#include "types.h"
#include "x509.h"
#include "config.h"

/* No authentication provided. */
#define EST_AUTH_TYPE_NONE      0x0

/* Basic auth provided */
#define EST_AUTH_TYPE_BASIC     0x1

/* X.509 Certificate auth provided. */
#define EST_AUTH_TYPE_CERT      0x2


// HTTP basic authentication requires username id and password secret
typedef struct ESTBasicAuth {
    char id[EST_BASIC_AUTH_ID_LEN];
    char secret[EST_BASIC_AUTH_SECRET_LEN];
}ESTBasicAuth_t;

typedef struct ESTPrivKey ESTPrivKey_t;

// Certificate authentication requires X.509 private key and certificate
typedef struct ESTCertAuth {
    /* Opacque private key. 
        Concrete type must be privided by the backend TLS implementation 
        Algorithm is not specified here (RSA, ECDSA, ...). 
    */
    ESTPrivKey_t *privateKey;

    /* Opacque X.509 certificate. 
        Concrete type must be privided by the backend TLS implementation 
    */
    ESTCertificate_t *certificate;
}ESTCertAuth_t;

typedef struct ESTAuthData {
    ESTBasicAuth_t basicAuth;
    ESTCertAuth_t certAuth;

    /* type field defines which auth is selected and configured. */
    byte_t type;
}ESTAuthData_t;


#endif /* D5F3F934_DFB4_4190_89B8_1926BFD61AE5 */
