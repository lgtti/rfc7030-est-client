# RFC7030 EST Client

[![CI/CD Pipeline](https://github.com/lorenzo/rfc7030-est-client/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/lorenzo/rfc7030-est-client/actions/workflows/ci.yml)
[![CodeQL Analysis](https://github.com/lorenzo/rfc7030-est-client/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/lorenzo/rfc7030-est-client/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Library and client implementation of EST Enrollment Protocol RFC 7030  
https://www.rfc-editor.org/rfc/rfc7030.html

## Table of Contents

1. [Why another EST Client](#1-why-another-est-client)
2. [EST Endpoints](#2-est-endpoints)
3. [Build](#3-build)
   - [3.1. Linux/MacOS](#31-linuxmacos)
   - [3.2. Windows](#32-windows)
4. [Supported Backends](#4-supported-backends)
5. [Custom TLS/X.509 Backend](#5-custom-tlsx509-backend)
   - [5.1. Function map](#51-function-map)
   - [5.2. Example](#52-example)
6. [Usage](#6-usage)
   - [6.1. Client](#61-client)
     - [6.1.1 Example](#611-example)
   - [6.2. Library](#62-library)
     - [6.2.1 With CMake](#621-with-cmake)
     - [6.2.2 Without CMake](#622-without-cmake)
7. [Tests](#7-tests)
8. [Integration Testing with Docker](#integration-testing-with-docker)
9. [Logging](#9-logging)
10. [Custom parameters](#10-custom-parameters)
11. [Contribution](#11-contribution)
12. [RFC Requirements](#12-rfc-requirements)
    - [12.1 RFC 8951](#121-rfc-8951)

## 1. Why another EST Client

Actually, the standard reference implementation https://github.com/cisco/libest is very complex (Android support, BRSKI support, ...).

Another problem with libest is the OpenSSL library used to implements all crypto capabilities because is the only supported library and the references are scattered in the code so is't easy to port to another library.

In the IoT world, we have devices with different SSL libraries (e.g. WolfSSL, BoringSSL, MbedTLS...) or different platforms that needs non-standard compilation methods or build chains (e.g. FreeRTOS and some market PLCs).

To support different platforms and libraries we need a 'pluggable' and configurable client.

## 2. EST Endpoints

| Endpoint | Status |
|----------|--------|
| `/cacerts` | ✅ IMPLEMENTED |
| `/simpleenroll` | ✅ IMPLEMENTED |
| `/simplereenroll` | ✅ IMPLEMENTED |
| `/fullcmc` | ❌ NOT IMPLEMENTED |
| `/csrattrs` | ❌ NOT IMPLEMENTED |

## 3. Build

### Compile Dependencies:
- picohttpparser
- munit (test only)
- cargs (cli client only)

> **Note:** All dependencies are downloaded automatically using git submodules.

Current cmake build configuration provides some default arguments you can on/off as you wish:

| Option | Description |
|--------|-------------|
| `BUILD_CLONE_SUBMODULES=ON` | Set to off to avoid clone third parts compile dependencies |
| `USE_OPENSSL=ON` | Current default TLS/X.509 backend implementation |
| `USE_OPENSSL_CUSTOM_ROOT=OFF` | Enable the variable USE_OPENSSL_CUSTOM_ROOT_PATH |
| `USE_OPENSSL_CUSTOM_ROOT_PATH=""` | Enabled using USE_OPENSSL_CUSTOM_ROOT=ON, sets the path used to find the openssl root dir |
| `USE_OPENSSL_MANUAL_LINK=OFF` | Enable manual link to openssl implementation (skip find_package) |
| `USE_OPENSSL_MANUAL_LINK_INC=""` | If manual link is ON, set the openssl include directory |
| `USE_OPENSSL_MANUAL_LINK_LIB=""` | If manual link is ON, set the openssl lib path (you need to set at least two libs, libssl and libcrypto). To setup multiple libraries use cmake list format eg. `USE_OPENSSL_MANUAL_LINK_LIB=/path/libssl.so\;/path/libcrypto.so` |

### 3.1. Linux/MacOS

**Setup cmake artifacts:**
```bash
cmake -Ssrc -Bbuild
```
> If you want to change the build output directory update the -B flag.

**Compile the code:**
```bash
cd build
make
```
> **Note:** At the end you will find the artifact `build/rfc7030-est-client`

**Run unit tests:**
```bash
./bin/rfc7030-est-client-tests
```

**Run integration tests:**
```bash
./bin/rfc7030-est-integration-tests
```
> **Note:** For detailed integration testing setup and Docker-based EST server configuration, see the documentation in the [`test/`](./test/) directory.

### 3.2. Windows

*[Windows build instructions would go here]*

## 4. Supported Backends

Here the table of native supported TLS/X.509 backends.

| Name | Folder | Version |
|------|--------|---------|
| OpenSSL | `src/openssl` | >= 1.x |

## 5. Custom TLS/X.509 Backend

As described in the general description, this EST implementation is agnostic regarding the runtime crypto library. If you need a non-compliant library you must create your backend following some rules and configuring the plugin.

The logic of the EST client is written in the `src/lib` folder but, to invoke the provided client with a backend, you need some additional operations, such as parse authentication certificates, parse certificate output result and other.

A new backend need to expose and implement ALL function definitions located in the header file `src/lib/include/rfc7030.h`

> **Note:** An example for OpenSSL is located in `src/openssl/openssl_rfc.c`

### 5.1. Function map

The core of the backend plugin is the config function map. Basically, is a set of function pointers used by the EST core library to invoke implementation-specific functions.

Two different maps are required:
- **ESTTLSInterface_t**: used to invoke TLS specific functions, such as init TLS channel and read/write bytes
- **ESTX509Interface_t**: used to parse, decode and encode specific X.509 objects such as Certificates, Store, PKCS7 formats

These maps MUST be configured by the backend (for example see the `src/openssl/openssl_rfc.c` file) and ALL function MUST be implemented. There aren't optional functions.

### 5.2. Example

For example, you want to add a myssl library implementation:

**1. Create new folder:**
```bash
src/myssl
```

**2. Create new file:**
```bash
src/myssl/myssl_rfc.c
```
> **Note:** This file must implement all functions definitions:
> - `rfc7030_init`
> - `rfc7030_get_config`
> - `rfc7030_request_cachain`
> - `rfc7030_request_certificate`
> - `rfc7030_renew_certificate`

**3. Create new cmake file:**
```bash
src/myssl/myssl_est_client_library.cmake
```
This file must expose all headers and source files required by the backend implementation. An example is `src/openssl/ossl_est_client_library.cmake`.

**4. Add the library to the `src/CMakeLists.txt` file:**
Please remember to add a new cmake option (disabled by default) to enable/disable the new backend. For this example could be:
```cmake
OPTION(USE_MYSSL "Compile using myssl backend" OFF)
```
> **Note:** Search in the file for the `### BEGIN OPENSSL SECTION` and replicate the OpenSSL section as example.

**5. Prepare cmake with flags:**
```bash
cmake -Ssrc -Bbuild -DUSE_MYSSL=ON -DUSE_OPENSSL=OFF
```

**6. Build the code:**
```bash
cd build
make
```

**7. Run tests:**
```bash
# Unit tests
./bin/rfc7030-est-client-tests

# Integration tests
./bin/rfc7030-est-integration-tests
# Note: For Docker-based EST server setup, see test/ directory documentation
```

## 6. Usage

Due to the generic nature of this EST implementation, you have the freedom to choose the type of usage you want.

You can compile the project and generate the command line client, you can build your own client logic using another backend or you can use the low level library and build you entire client from scratch. In addition you can use the current client logic without all "cli" feature importing the code in your project.

### 6.1. Client

Located in the `src/client` directory, this is a command line interface client.

You can run:
```bash
./rfc7030_est_client -h
```
to view the list of input parameters.

#### 6.1.1 Example

First of all, from the http://testrfc7030.com website you must download the server chain dstcax3.pem using the command:
```bash
wget http://testrfc7030.com/dstcax3.pem
```

With the client you can run three main operations:

**CACerts**
```bash
./rfc7030-est-client -s testrfc7030.com \
    -p 8443 \
    --server-chain dstcax3.pem \
    --output cachain.pem \
    cacerts
```
This command request to the EST server the list of CA certificates. No authentication is required here.

**Enroll**

This command request to the EST Server the emission of a certificate providing a local csr (p10) file in PEM format. Here we need authentication:

*Basic Auth:*
```bash
./rfc7030-est-client -s testrfc7030.com \
    -p 8443 \
    --server-chain dstcax3.pem \
    --csr req.p10 \
    --basic-auth "estuser:estpwd" \
    --output-ca cachain.pem \
    --output-crt enrolled.pem \
    enroll
```

*TLS Auth:*
```bash
./rfc7030-est-client -s testrfc7030.com \
    -p 9443 \
    --server-chain dstcax3.pem \
    --csr req.p10 \
    --p12 preenrollment.p12 \
    --p12-password "12345" \
    --output-ca cachain.pem \
    --output-crt enrolled.pem \
    enroll
```

**Renew**

This command request to the EST Server the emission of a certificate that renews an old one providing a local csr (p10) file in PEM format and the old certificate (and its key) in P12.

The syntax of the command is the same as the Enroll changing the p12 file and the last command renew.

### 6.2. Library

If you don't want (or you can't) use the pre-compiled client or you want to include the EST client in your code, you can write your own using the EST core library.

This project is not developed with the idea to generate a shared or dynamic library. To address PLC or low level hardware implementations, the code MUST be compiled with the source code of the client. This makes the library compatible with FreeRTOS also.

The drawback is that you must clone this repo and add to your build toolchain all required headers and source files.

To use all library functions you need to include only one header file:
```c
#include <est.h>
```

and this provides to you the access to all low level functions (prefixed with `est_xxx`) and all low level "client" functions (prefixed with `est_client_xxx`).

> **Note:** See the `src/openssl/openssl_rfc.c` file to check how to use low level EST library functions.

#### 6.2.1 With CMake

If you are using cmake, you can add all required file using the provided cmake import file:
```cmake
include(${MODULE_ROOT_DIR}/src/lib/est_library.cmake)
```
> **Note:** This include provides to you cmake config some variables:
> - `EST_SRC`
> - `EST_HEADERS`

In addition, if you want to use an already implemented backend, you must add it in the same way. Here the example for OpenSSL:
```cmake
include(${MODULE_ROOT_DIR}/src/openssl/ossl_est_client_library.cmake)
```
> **Note:** This include provides to you cmake config some variables:
> - `EST_OPENSSL_SRC`
> - `EST_OPENSSL_SRC_TEST`
> - `EST_OPENSSL_HEADERS`

#### 6.2.2 Without CMake

If you don't want to use cmake or you need another compile manager you can directly link all required headers and source files.

**Set the include directory:**
- `src/lib/include`
- `src/third_party/picohttpparser`

**Set the src files to link:**
- `src/lib/cacerts.c`
- `src/lib/client.c`
- `src/lib/enroll.c`
- `src/lib/error.c`
- `src/lib/est.c`
- `src/lib/http.c`
- `src/lib/picohttp.c`
- `src/third_party/picohttpparser/picohttpparser.c`

To link the selected backend you need to do the same.

## 7. Tests

**Run unit tests:**
```bash
./bin/rfc7030-est-client-tests
```

**Run integration tests:**
```bash
./bin/rfc7030-est-integration-tests
```
> **Note:** Integration tests need internet connection to reach the EST public welcome server. For detailed setup with Docker-based EST server and automated testing, see the comprehensive documentation in the [`test/`](./test/) directory.

## Integration Testing with Docker

For comprehensive integration testing with a local EST server, this project includes a complete Docker-based testing environment in the [`test/`](./test/) directory.

### Features:
- **Dockerized Cisco/libest EST Server** with dual-port configuration (TLS 8443, mTLS 9443)
- **Real certificate issuance** with OpenSSL CA backend
- **Persistent CA database** using Docker volumes
- **Automated test runner** script for complete CI/CD integration
- **Comprehensive documentation** with setup, usage, and troubleshooting guides

### Quick Start:
```bash
cd test/
./run-integration-tests.sh
```

This will automatically:
1. Build the EST server Docker image
2. Start the EST server with proper configuration
3. Run all integration tests against the local server
4. Display results and server logs

For detailed setup instructions, configuration options, and troubleshooting, see the [`test/README.md`](./test/README.md) file.

## 9. Logging

Some HW platforms requires a specific logging implementation. This library doesn't provided any default one, instead offers some macros to be implemented using platform-specific code. The default implementation is a no-ops impl.

The `src/lib/include/config.h` header file contains:
```c
#ifdef EST_CONFIG_CUSTOM_FILE
#include EST_CONFIG_CUSTOM_FILE
#endif
```

During CMake build you can define this macro specifying a header file that redefines the logging functions. For example, if you call cmake with:
```bash
cmake ... -DEST_CONFIG_CUSTOM_FILE=mylog.h
```

the file must contains:
```c
#include "logger.h"

#undef LOG_INFO
#define LOG_INFO(m) log_info m;

#undef LOG_DEBUG
#define LOG_DEBUG(m) log_debug m;

#undef LOG_WARN
#define LOG_WARN(m) log_warn m;

#undef LOG_ERROR
#define LOG_ERROR(m) log_error m;
```

where `log_xxx` are platform specific logging functions implemented and linked in your code.

## 10. Custom parameters

Same as for logging, you can use the macro:
```bash
cmake ... -DEST_CONFIG_CUSTOM_FILE=mylog.h
```

you can undefine and redefine all EST runtime parameters, adapting them to you specific HW or environment. For example:
```c
#undef HTTP_RESP_CHUNK_LEN
#define HTTP_RESP_CHUNK_LEN 10000
```

changes the default value of the HTTP download payload from the default to 10KB.

## 11. Contribution

If you want to submit a fix or a new backend implementation feel free to provide the pull request. Any contribution is welcome :)

Please open a github issue for any question.

## 12. RFC Requirements

The list of RFC requirements.

| Level | RFC | Status |
|-------|-----|--------|
| **MUST** | Verifying the EST server's HTTPS URI against the EST server's certificate using Implicit TAs (similar to a common HTTPS exchange) | ✅ IMPLEMENTED |
| **MUST** | The client MUST NOT respond to the server's HTTP authentication request unless the client has authorized the EST server | ✅ IMPLEMENTED |
| **MUST** | Certificate validation MUST be performed as per [RFC5280]. The EST server certificate MUST conform to the [RFC5280] certificate profile | ✅ IMPLEMENTED |
| **OPTIONAL** | The client can leverage the binding of a shared credential to a specific EST server with a certificate-less TLS cipher suite | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | TLS with a previously issued client certificate (e.g., an existing certificate issued by the EST CA) | ✅ IMPLEMENTED |
| **OPTIONAL** | TLS with a previously installed certificate (e.g., manufacturer-installed certificate or a certificate issued by some other party) | ✅ IMPLEMENTED |
| **?** | Certificate-less TLS (e.g., with a shared credential distributed out-of-band) | ❌ NOT IMPLEMENTED |
| **MUST** | HTTP-based with a username/password distributed out-of-band | ✅ IMPLEMENTED |
| **OPTIONAL** | A client MAY set the username to the empty string ("") if it is presenting a password that is not associated with a username | ✅ IMPLEMENTED |
| **OPTIONAL** | The client is expected to retry the request, including the appropriate Authorization Request header ([RFC2617], Section 3.2.2), if the client is capable of using the Basic or Digest authentication | ❌ NOT IMPLEMENTED |
| **MUST** | The client MUST wait at least the specified "retry-after" time before repeating the same request. The client repeats the initial enrollment request after the appropriate "retry-after" interval has expired | ❌ NOT IMPLEMENTED |
| **MUST** | EST clients request a certificate from the EST server with an HTTPS POST using the operation path value of "/simpleenroll" | ✅ IMPLEMENTED |
| **MUST** | EST clients request a renew/rekey of existing certificates with an HTTP POST using the operation path value of "/simplereenroll" | ✅ IMPLEMENTED |
| **MUST** | The client MUST also be able to request CA certificates from the EST server and parse the returned "bag" of certificates using /cacerts | ✅ IMPLEMENTED |
| **MUST** | The EST client uses the /cacerts response to establish an Explicit Trust Anchor database for subsequent TLS authentication of the EST server | ✅ IMPLEMENTED |
| **MUST** | EST clients MUST NOT engage in any other protocol exchange until after the /cacerts response has been accepted and a new TLS session has been established (using TLS certificate-based authentication) | ✅ IMPLEMENTED |
| **OPTIONAL** | Clients SHOULD request an up-to-date response before stored information has expired in order to ensure the EST CA TA database is up to date | ❌ NOT IMPLEMENTED |
| **MUST** | If the client disables the Implicit TA database and if the EST server certificate was verified using an Implicit TA database entry then the client MUST include the "Trusted CA Indication" extension in future TLS sessions [RFC6066] | ❌ NOT IMPLEMENTED |
| **MUST** | The EST server SHOULD include the three "Root CA Key Update" certificates OldWithOld, OldWithNew, and NewWithOld in the response chain. The EST client MUST be able to handle these certificates in the response | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | Implementations conforming to this standard MUST provide the ability to designate Explicit Tas | ✅ IMPLEMENTED |
| **MUST** | After out-of-band validation occurs, all the other certificates MUST be validated using normal [RFC5280] certificate path validation (using the most recent CA certificate as the TA) before they can be used to build certificate paths during certificate validation | ✅ IMPLEMENTED |
| **OPTIONAL** | For human usability reasons, a "fingerprint" of an Explicit TA database entry can be configured for bootstrapping as discussed in Section 4.1.1 | ❌ NOT IMPLEMENTED |
| **MUST** | Implementations conforming to this standard MUST provide the ability to disable use of any Implicit TA database | ✅ IMPLEMENTED |
| **MUST** | The client MUST maintain a distinction between the use of Explicit and Implicit TA databases during authentication in order to support proper authorization | ✅ IMPLEMENTED |
| **OPTIONAL** | The client MAY provisionally continue the TLS handshake to completion for the purposes of accessing the /cacerts or /fullcmc method | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | If the EST client continues with an unauthenticated connection, the client MUST extract the HTTP content data from the response (Sections 4.1.3 or 4.3.2) and engage a human user to authorize the CA certificate using out-of-band data such as a CA certificate "fingerprint" (e.g., a SHA-256 or SHA-512 [SHS] hash on the whole CA certificate) | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | The EST client can be configured with a tuple composed of the authority portion of the URI along with the OPTIONAL label (e.g., "www.example.com:80" and "arbitraryLabel1") | ✅ IMPLEMENTED |
| **OPTIONAL** | HTTP redirections (3xx status codes) to the same web origin (see [RFC6454]) SHOULD be handled by the client without user input so long as all applicable security checks | ❌ NOT IMPLEMENTED |
| **MUST** | HTTPS MUST be used. TLS 1.1 [RFC4346] (or a later version) MUST be used for all EST communications | ✅ IMPLEMENTED |
| **OPTIONAL** | TLS session resumption [RFC5077] SHOULD be supported When performing renegotiation, TLS "secure_renegotiation" RFC5746 MUST be used | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | The client can determine if the server requires the linking of identity and POP by examining the CSR Attributes Response | ❌ NOT IMPLEMENTED |
| **OPTIONAL** | Regardless of the CSR Attributes Response, clients SHOULD link identity and POP by embedding tls-unique information in the certification request | ✅ IMPLEMENTED |

### 12.1 RFC 8951

Thanks to https://github.com/61131 a first support for the RFC 8951 https://datatracker.ietf.org/doc/html/rfc8951 has been added.

| Level | RFC | Status |
|-------|-----|--------|
| **MUST** | RFC-8951 This document updates [RFC7030] to require the POST request and payload response of all endpoints using base64 encoding, as specified in Section 4 of [RFC4648]. In both cases, the Distinguished Encoding Rules (DER) [X.690] are used to produce the input for the base64 encoding routine. This format is to be used regardless of any Content-Transfer-Encoding header, and any value in such a header MUST be ignored | ✅ IMPLEMENTED |

> **Note:** New client flag (propagated in the EST library in option structure) has been add to skip this RFC implementation.
