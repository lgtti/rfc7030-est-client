#ifndef EFBACCEC_6650_4D17_95C1_ED2EA1CA15A6
#define EFBACCEC_6650_4D17_95C1_ED2EA1CA15A6

#include "logger.h"

#undef LOG_INFO
#define LOG_INFO(m) log_info m;

#undef LOG_DEBUG
#define LOG_DEBUG(m) log_debug m;

#undef LOG_WARN
#define LOG_WARN(m) log_warn m;

#undef LOG_ERROR
#define LOG_ERROR(m) log_error m;

#define CLIENT_CACERT_MAX_LEN       100000 // 48 certificates with 2048 byte size 
#define CLIENT_ENROLLED_MAX_LEN     5000 // RSA certificate in PEM format with 4096 bits of key is tipically max 2048 bytes

#endif /* EFBACCEC_6650_4D17_95C1_ED2EA1CA15A6 */
