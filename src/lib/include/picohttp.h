#ifndef E8F8678A_8AAB_48BB_8DE0_D3100AB12C38
#define E8F8678A_8AAB_48BB_8DE0_D3100AB12C38

#include "http.h"

ESTHttp_Ctx_t * picohttp_initialize(TransportInterface_t *tint, const ESTAuthData_t *auth, ESTError_t *err);
bool_t picohttp_send(ESTHttp_Ctx_t *ctx, ESTHttp_ReqMetadata_t *request_metadata, byte_t *body, size_t body_len, ESTHttp_RespMetadata_t *response_metadata, ESTError_t *err);
void picohttp_send_free(ESTHttp_Ctx_t *ctx, ESTHttp_RespMetadata_t *response_metadata);
void picohttp_free(ESTHttp_Ctx_t *ctx);

#endif /* E8F8678A_8AAB_48BB_8DE0_D3100AB12C38 */
