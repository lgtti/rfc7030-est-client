# rfc7030-est-client

Library and client implementation of EST Enrollment Protocol RFC 7030 [https://www.rfc-editor.org/rfc/rfc7030.html](https://www.rfc-editor.org/rfc/rfc7030.html)

## Why another EST Client
Actually the standard reference implementation [https://github.com/cisco/libest](https://github.com/cisco/libest) 
is very complex and with a support for Android platform. In addition, this version uses a specific OpenSSL library version.

In the IoT world, we have some devices with different SSL libraries (e.g. WolfSSL, BoringSSL, MbedTLS...) or different platforms (e.g. FreeRTOS).

To support different platforms and libraries we need a 'pluggable' client.

## Repository structure
### Library
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