#ifndef CLIENT_RFC_7030_H
#define CLIENT_RFC_7030_H

#include "est.h"

typedef bool_t (*parse_p12_t)(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err);
typedef bool_t (*parse_basicauth_t)(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err);

typedef struct RFC7030_Subsystem_Config {
    const ESTTLSInterface_t *tls;
    const ESTX509Interface_t *x509;
    parse_p12_t parse_p12;
    parse_basicauth_t parse_basicauth;
    est_get_csr_t get_csr;
}RFC7030_Subsystem_Config_t;

typedef struct RFC7030_Options {
    int port;
    const char *host;
    const char *label;
    const char *cachain;
    bool_t disable_rfc8951;
}RFC7030_Options_t;

typedef struct CstCtx CsrCtx_t;

typedef struct RFC7030_Enroll_Options {
    RFC7030_Options_t opts;
    ESTAuthData_t auth;
    CsrCtx_t *csr_ctx;
}RFC7030_Enroll_Options_t;

void rfc7030_init();

RFC7030_Subsystem_Config_t * rfc7030_get_config();

bool_t rfc7030_request_cachain(RFC7030_Options_t *config, 
    char *ca, 
    size_t ca_len, 
    ESTError_t *err
);

bool_t rfc7030_request_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
);

bool_t rfc7030_renew_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
);

#endif