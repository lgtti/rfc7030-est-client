set(EST_SRC 
    ${MODULE_ROOT_DIR}/src/lib/cacerts.c
    ${MODULE_ROOT_DIR}/src/lib/client.c
    ${MODULE_ROOT_DIR}/src/lib/enroll.c
    ${MODULE_ROOT_DIR}/src/lib/error.c
    ${MODULE_ROOT_DIR}/src/lib/est.c
    ${MODULE_ROOT_DIR}/src/lib/http.c
    ${MODULE_ROOT_DIR}/src/lib/picohttp.c

    ${HTTP_PARSER_SRC}
)

set(EST_HEADERS
    ${MODULE_ROOT_DIR}/src/lib/include

    ${HTTP_PARSER_INC}
)

message( "${EST_HEADERS}" )
message( "${EST_SRC}" )