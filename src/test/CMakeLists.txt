# Project information.
cmake_minimum_required ( VERSION 3.18.0 )
project ( "RFC7030-EST-Clients-Test"
          VERSION 1.0.0
          LANGUAGES C )

add_executable(rfc7030-est-client-tests
        ${EST_SRC}
        logger.c
        main.c)

target_include_directories(rfc7030-est-client-tests
                            PRIVATE 
                            .
                            ${EST_HEADERS})

target_include_directories(rfc7030-est-client-tests PRIVATE 
    ${SSL_INCLUDE_DIR} 
    ${MUNIT_DIR}
)

target_link_libraries(rfc7030-est-client-tests ${SSL_LIBRARIES})
target_sources(rfc7030-est-client-tests PRIVATE ${SSL_SRC} ${SSL_SRC_TEST} ${MUNIT_DIR}/munit.c)
target_compile_definitions(rfc7030-est-client-tests PRIVATE EST_CONFIG_CUSTOM_FILE="custom_config.h")
target_compile_definitions(rfc7030-est-client-tests PRIVATE MUNIT_NO_FORK)

add_compile_definitions(TEST_RESOURCE_FOLDER="${MODULE_ROOT_DIR}/src/test/res")
