set(EST_OPENSSL_SRC 
    ${MODULE_ROOT_DIR}/src/openssl/openssl.c
    ${MODULE_ROOT_DIR}/src/openssl/openssl_tls.c
    ${MODULE_ROOT_DIR}/src/openssl/openssl_x509.c
    ${MODULE_ROOT_DIR}/src/openssl/openssl_rfc.c
)

set(EST_OPENSSL_SRC_TEST 
    ${MODULE_ROOT_DIR}/src/openssl/openssl_test.c
)

set(EST_OPENSSL_HEADERS
    ${MODULE_ROOT_DIR}/src/openssl
)

message( "${EST_OPENSSL_SRC}" )
message( "${EST_OPENSSL_SRC_TEST}" )
message( "${EST_OPENSSL_HEADERS}" )