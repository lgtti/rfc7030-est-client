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

#endif /* EFBACCEC_6650_4D17_95C1_ED2EA1CA15A6 */
