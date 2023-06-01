# Project information.
cmake_minimum_required ( VERSION 3.20.2 )
project ( "RFC7030-EST-Clients"
          VERSION 1.0.0
          LANGUAGES C )

add_executable(rfc7030-est-client 
        ${EST_SRC}
        logger.c
        main.c)

target_include_directories(rfc7030-est-client 
                            PRIVATE 
                            .
                            ${EST_HEADERS})

target_include_directories(rfc7030-est-client PRIVATE ${SSL_INCLUDE_DIR} ${EST_OPENSSL_HEADERS})
target_link_libraries(rfc7030-est-client ${SSL_LIBRARIES})
target_sources(rfc7030-est-client PRIVATE ${SSL_SRC})
target_link_libraries(rfc7030-est-client cargs)
target_compile_definitions(rfc7030-est-client PRIVATE EST_CONFIG_CUSTOM_FILE="custom_config.h")


