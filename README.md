# rfc7030-est-client

## Why another EST Client
Actually the standard reference implementation [https://github.com/cisco/libest](https://github.com/cisco/libest) 
is very complex and with a support for Android platform. In addition, this version uses a specific OpenSSL library version.

In the IoT world, we have some devices with different SSL libraries (e.g. WolfSSL, BoringSSL, MbedTLS...) or different platforms (e.g. FreeRTOS).

To support different platforms and libraries we need a 'pluggable' client.

