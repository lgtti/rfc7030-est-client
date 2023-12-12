# Project information.
cmake_minimum_required ( VERSION 3.18.0 )
project ( "RFC7030-EST-Integration-Test"
          VERSION 1.0.0
          LANGUAGES C )

add_executable(rfc7030-est-integration-tests
        ${EST_SRC}
        logger.c
        main.c)

target_include_directories(rfc7030-est-integration-tests
                            PRIVATE 

                            .
                            ${EST_HEADERS})

target_include_directories(rfc7030-est-integration-tests PRIVATE 
    ${SSL_INCLUDE_DIR} 
    ${MUNIT_DIR}
)

target_link_libraries(rfc7030-est-integration-tests ${SSL_LIBRARIES})
target_sources(rfc7030-est-integration-tests PRIVATE ${SSL_SRC} ${SSL_SRC_TEST} ${MUNIT_DIR}/munit.c)

OPTION(USE_CUSTOM_CONFIG "Option description" ON)
if(USE_CUSTOM_CONFIG)
    target_compile_definitions(rfc7030-est-integration-tests PRIVATE EST_CONFIG_CUSTOM_FILE="custom_config.h")
endif()

target_compile_definitions(rfc7030-est-integration-tests PRIVATE MUNIT_NO_FORK)

add_compile_definitions(TEST_RESOURCE_FOLDER="${MODULE_ROOT_DIR}/src/integration/res")
