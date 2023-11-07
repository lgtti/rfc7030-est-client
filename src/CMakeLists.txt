# Project information.
cmake_minimum_required ( VERSION 3.20.2 )
project ( "RFC7030-EST"
          VERSION 1.0.0
          LANGUAGES C )

# Allow the project to be organized into folders.
set_property( GLOBAL PROPERTY USE_FOLDERS ON )

# Use C99.
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )

# Do not allow in-source build.
if( ${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR} )
    message( FATAL_ERROR "In-source build is not allowed. Please build in a separate directory, such as ${PROJECT_SOURCE_DIR}/build." )
endif()

# Set global path variables.
get_filename_component(__MODULE_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(MODULE_ROOT_DIR ${__MODULE_ROOT_DIR} CACHE INTERNAL "est repository root.")

# Configure options for clone submodules
option( BUILD_CLONE_SUBMODULES
        "Set this to ON to automatically clone any required Git submodules. When OFF, submodules must be manually cloned."
        ON )

# Set output directories.
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )


# ===================== Clone needed third-party libraries ======================
find_package( Git REQUIRED )
    
# Setup git submodules folders
# - https://github.com/h2o/picohttpparser
# - https://github.com/likle/cargs
# - https://github.com/nemequ/munit

# Check if the picohttpparser source directory exists.
set( HTTP_PARSER_DIR ${MODULE_ROOT_DIR}/src/third_party/picohttpparser CACHE INTERNAL "http_parser library source directory." )
if( NOT EXISTS ${HTTP_PARSER_DIR}/picohttpparser.c )
    # Attempt to clone picohttpparser.
    if( ${BUILD_CLONE_SUBMODULES} ) 
        message( "Cloning submodule picohttpparser." )
        execute_process( COMMAND ${GIT_EXECUTABLE} submodule add https://github.com/h2o/picohttpparser ${HTTP_PARSER_DIR}
                                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                                RESULT_VARIABLE HTTP_PARSER_CLONE_RESULT )
        
        if( NOT ${HTTP_PARSER_CLONE_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to clone https://github.com/h2o/picohttpparser submodule." )
        endif()
    else()
        message( FATAL_ERROR "The required submodule https://github.com/h2o/picohttpparser does not exist. Either clone it manually, or set BUILD_CLONE_SUBMODULES to 1 to automatically clone it during build." )
    endif()
endif()

set(HTTP_PARSER_INC ${HTTP_PARSER_DIR})
set(HTTP_PARSER_SRC ${HTTP_PARSER_DIR}/picohttpparser.c)


# Check if the cargs source directory exists.
set( CARGS_DIR ${MODULE_ROOT_DIR}/src/third_party/cargs CACHE INTERNAL "cargs library source directory." )
if( NOT EXISTS ${CARGS_DIR}/src/cargs.c )
    # Attempt to clone cargs.
    if( ${BUILD_CLONE_SUBMODULES} ) 
        message( "Cloning submodule cargs." )
        execute_process( COMMAND ${GIT_EXECUTABLE} submodule add https://github.com/likle/cargs ${CARGS_DIR}
                                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                                RESULT_VARIABLE CARGS_DIR_CLONE_RESULT )
        
        if( NOT ${CARGS_DIR_CLONE_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to clone https://github.com/likle/cargs submodule." )
        endif()
    else()
        message( FATAL_ERROR "The required submodule https://github.com/likle/cargs does not exist. Either clone it manually, or set BUILD_CLONE_SUBMODULES to 1 to automatically clone it during build." )
    endif()
endif()

add_subdirectory(${CARGS_DIR}) 


# Check if the munit source directory exists.
set( MUNIT_DIR ${MODULE_ROOT_DIR}/src/third_party/munit CACHE INTERNAL "munit library source directory." )
if( NOT EXISTS ${MUNIT_DIR}/munit.c )
    # Attempt to clone cargs.
    if( ${BUILD_CLONE_SUBMODULES} ) 
        message( "Cloning submodule munit." )
       execute_process( COMMAND ${GIT_EXECUTABLE} submodule add https://github.com/nemequ/munit ${MUNIT_DIR}
                                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                                RESULT_VARIABLE MUNIT_DIR_CLONE_RESULT )
        
        if( NOT ${MUNIT_DIR_CLONE_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to clone https://github.com/nemequ/munit submodule." )
        endif()
    else()
        message( FATAL_ERROR "The required submodule https://github.com/nemequ/munit does not exist. Either clone it manually, or set BUILD_CLONE_SUBMODULES to 1 to automatically clone it during build." )
    endif()
endif()


include(${MODULE_ROOT_DIR}/src/lib/est_library.cmake)


### BEGIN OPENSSL SECTION

include(${MODULE_ROOT_DIR}/src/openssl/ossl_est_client_library.cmake)

OPTION(USE_OPENSSL "Compile using openssl backend" ON)
OPTION(USE_OPENSSL_MANUAL_LINK "Ignore find_package and manually link include and lib" OFF)
OPTION(USE_OPENSSL_MANUAL_LINK_INC "Set openssl include dir" /usr/include)
OPTION(USE_OPENSSL_MANUAL_LINK_LIB "Set openssl lib dir" /usr/lib64)
OPTION(USE_OPENSSL_CUSTOM_ROOT "Custom openssl path" OFF)
OPTION(USE_OPENSSL_CUSTOM_ROOT_PATH "Custom openssl path" /usr/local/opt/openssl)

if(USE_OPENSSL)
    if(USE_OPENSSL_MANUAL_LINK)
        set(OPENSSL_INCLUDE_DIR ${USE_OPENSSL_MANUAL_LINK_INC})
        set(OPENSSL_LIBRARIES ${USE_OPENSSL_MANUAL_LINK_LIB})
    else()
        if(USE_OPENSSL_CUSTOM_ROOT)
            set(OPENSSL_ROOT_DIR USE_OPENSSL_CUSTOM_ROOT_PATH)
        else()
            if(APPLE)
                set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
            endif()
        endif()

        find_package(OpenSSL REQUIRED)
        message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
        message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
        message("OpenSSL version: ${OPENSSL_VERSION}")

        if(OPENSSL_VERSION VERSION_LESS "1.1")
            message( FATAL_ERROR "Required OPENSSL Version greater than 1.0" )
        endif()
    endif()

    # Define here global SSL agnostic references to this specific OpenSSL Implementation.
    set(SSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR} ${EST_OPENSSL_HEADERS})
    set(SSL_LIBRARIES ${OPENSSL_LIBRARIES})
    set(SSL_SRC ${EST_OPENSSL_SRC})
    set(SSL_SRC_TEST ${EST_OPENSSL_SRC_TEST})
else()
    message( FATAL_ERROR "No SSL/TLS backend specified. " )
endif()

### END OPENSSL SECTION

add_subdirectory(${MODULE_ROOT_DIR}/src/client)
add_subdirectory(${MODULE_ROOT_DIR}/src/test)
add_subdirectory(${MODULE_ROOT_DIR}/src/integration)





