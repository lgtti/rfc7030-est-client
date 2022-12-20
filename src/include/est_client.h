#ifndef B2D50D41_6CA8_4FB3_A3E8_6BE8F524E276
#define B2D50D41_6CA8_4FB3_A3E8_6BE8F524E276

#include "est.h"

typedef void (*EST_client_enroll_event)(const ESTCaCerts_Info_t *cacerts, const ESTCertificate_t *crt);

bool_t enroll_certificate(const ESTClient_Options_t *opts, 
                            const ESTAuthData_t *auth, 
                            const char *host, 
                            int port, 
                            byte_t *csr,
                            size_t csr_len,
                            EST_client_enroll_event event,
                            ESTError_t *err);

bool_t reenroll_certificate(const ESTClient_Options_t *opts, 
                            const ESTAuthData_t *auth, 
                            const char *host, 
                            int port, 
                            byte_t *csr,
                            size_t csr_len,
                            EST_client_enroll_event event,
                            ESTError_t *err);

#endif /* B2D50D41_6CA8_4FB3_A3E8_6BE8F524E276 */
