#ifndef D5F3F934_DFB4_4190_89B8_1926BFD61A32
#define D5F3F934_DFB4_4190_89B8_1926BFD61A32

#include "est.h"

/* EST internal definition of the incomplete type defined in the est.h header.
 It contains all data used by internal client logic.*/
struct ESTClient_Ctx {
    ESTClient_Options_t options;

    /* Interface with raw transport layer.
        For example, if you are in an embedded world, this interface
        can point to a hw-oriented driver that write socket data.
    */
    TransportInterface_t transport;

    /* Context for HTTP layer */
    ESTHttp_Ctx_t *http;

    /* Hostname without port, usually used in HTTP commands
        as SNI parameter. */
    char host[EST_HTTP_HOST_PORT_LEN];

    /* Interface for the selected HTTP implementation.*/
    ESTHttpInterface_t httpInterface;

    /* TLS Unique POP information */
    char tlsunique[EST_TLS_UNIQUE_LEN];
    size_t tlsunique_len;

};

#endif 