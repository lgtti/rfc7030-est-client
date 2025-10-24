set(EST_MBEDTLS_SRC 
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls.c
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls_tls.c
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls_pkcs7.c
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls_x509.c
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls_rfc.c
)

set(EST_MBEDTLS_SRC_TEST
    ${MODULE_ROOT_DIR}/src/mbedtls/mbedtls_test.c
)

set(EST_MBEDTLS_HEADERS
    ${MODULE_ROOT_DIR}/src/mbedtls
)

message( "${EST_MBEDTLS_SRC}" )
message( "${EST_MBEDTLS_SRC_TEST}" )
message( "${EST_MBEDTLS_HEADERS}" )