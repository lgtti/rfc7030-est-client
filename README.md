# rfc7030-est-client

Library and client implementation of EST Enrollment Protocol RFC 7030 [https://www.rfc-editor.org/rfc/rfc7030.html](https://www.rfc-editor.org/rfc/rfc7030.html)

## Why another EST Client
Actually the standard reference implementation [https://github.com/cisco/libest](https://github.com/cisco/libest) 
is very complex (Android support, BRSKI support, ...).

Another problem with libest is the SSL library implementation used: openssl. Currently is the only supported backend and change this is not so easy (the code is made by openssl calls).

In the IoT world, we have devices with different SSL libraries (e.g. WolfSSL, BoringSSL, MbedTLS...) or different platforms that need non-standard compilation methods or build chainsd (e.g. FreeRTOS and some market PLCs).

To support different platforms and libraries we need a 'pluggable' and configurable client.

## The project
This repository contains three different types of EST clients. You need to choose the correct one based on some conditions and configuration or needs.

### EST raw library
Located in <b>src/lib</b> folder, is the real EST implementation.
This implementation is not a fully functional client but a very low level set of methods prefixed by est_xxx which implements all techical parts of the protocol.

#### Library
The /src folder contains all the code required by the EST library. This library is only the implementation of the protocol without any logic. 

#### CMake
If you want to use the library without a client you can import the source code in you project using the provided cmake import file /src/est_library.cmake.

For example:
```
include(${EST_LIBRARY_DIR}/src/est_library.cmake)
```

#### Other
If you are not using CMake you can import the library using your preferred tool or using classic importing procedure.

You need to add /src/include as include directory.

You need to add /src/ as linked directory.

### Reference implementation
Client folder contains the reference implementation for a standard client using the EST library. 

#### OpenSSL
##### Supported versions
#### mbedTLS
#### wolfSSL

## Build