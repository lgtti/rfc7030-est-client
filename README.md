# rfc7030-est-client

Library and client implementation of EST Enrollment Protocol RFC 7030 [https://www.rfc-editor.org/rfc/rfc7030.html](https://www.rfc-editor.org/rfc/rfc7030.html)

## Why another EST Client
Actually the standard reference implementation [https://github.com/cisco/libest](https://github.com/cisco/libest) 
is very complex (Android support, BRSKI support, ...).

Another problem with libest is the SSL library implementation used: openssl. Currently is the only supported backend and change this is not so easy (the code is made by openssl calls).

In the IoT world, we have devices with different SSL libraries (e.g. WolfSSL, BoringSSL, MbedTLS...) or different platforms that need non-standard compilation methods or build chainsd (e.g. FreeRTOS and some market PLCs).

To support different platforms and libraries we need a 'pluggable' and configurable client.

## RFC7030 - EST Requirements 
### Endpoint details
|Endpoint|Status|
|--------|------|
|/cacerts|IMPLEMENTED|
|/simpleenroll|IMPLEMENTED|
|/simplereenroll|IMPLEMENTED|
|/fullcmc|NOT IMPLEMENTED|
|/csrattrs|NOT IMPLEMENTED|
### Detailed requirement table
|RFC Chapter ref|Requirement description|Level|Status|Test
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- | --------------- | ---------------------------------------------------------------------------------------------- |
| 2.1.  Obtaining CA Certificates<br>3.2.3.  HTTP-Based Client Authentication<br>3.3.1.  TLS-Based Server Authentication<br>3.6.  Server Authorization<br>4.1.1.  Bootstrap Distribution of CA Certificates | Verifying the EST server's HTTPS URI against the EST server's certificate using Implicit TAs (similar to a common HTTPS exchange).<br>The client MUST NOT respond to the server's HTTP authentication request unless the client has authorized the EST server.<br>Certificate validation MUST be performed as per [RFC5280].  The EST server certificate MUST conform to the [RFC5280] certificate profile                                                                                            | MUST                                     | IMPLEMENTED     | test_client_enroll_invalid_est_ta                                                              |
| 3.3.  TLS Layer                                                                                                                                                                                           | The client can leverage the binding of a shared credential to a specific EST server with a certificate-less TLS cipher suite                                                                                                                                                                                                                                                                                                                                                                          | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 2.2.  Initial Enrollment<br>2.2.1.  Certificate TLS Authentication<br>3.3.2.  TLS-Based Client Authentication                                                                                             | TLS with a previously issued client certificate (e.g., an existing certificate issued by the EST CA);                                                                                                                                                                                                                                                                                                                                                                                                 | OPTIONAL                                 | IMPLEMENTED     | test_client_enroll_crt                                                                         |
| 2.2.  Initial Enrollment<br>3.3.2.  TLS-Based Client Authentication                                                                                                                                       | TLS with a previously installed certificate (e.g., manufacturer-installed certificate or a certificate issued by some other party);                                                                                                                                                                                                                                                                                                                                                                   | OPTIONAL                                 | IMPLEMENTED     | test_client_enroll_crt                                                                         |
| 2.2.  Initial Enrollment<br>2.2.2.  Certificate-Less TLS Authentication<br>3.3.2.  TLS-Based Client Authentication<br>3.3.3.  Certificate-Less TLS Mutual Authentication                                  | Certificate-less TLS (e.g., with a shared credential distributed out-of-band);                                                                                                                                                                                                                                                                                                                                                                                                                        |                                          | NOT IMPLEMENTED |                                                                                                |
| 2.2.  Initial Enrollment<br>2.2.3.  HTTP-Based Client Authentication<br>3.2.3.  HTTP-Based Client Authentication<br>3.3.2.  TLS-Based Client Authentication                                               | HTTP-based with a username/password distributed out-of-band.<br>A client MAY set the username to the empty string ("") if it is presenting a password that is not associated with a username                                                                                                                                                                                                                                                                                                          | MUST<br>(NB: MAY for the enpty username) | IMPLEMENTED     | test_client_enroll_basic                                                                       |
| 3.2.3.  HTTP-Based Client Authentication                                                                                                                                                                  | Servers that wish to use Basic and Digest authentication reject the HTTP request using the HTTP-defined WWW-Authenticate response-header ([RFC2616], Section 14.47).  The client is expected to retry the request, including the appropriate Authorization Request header ([RFC2617], Section 3.2.2), if the client is capable of using the Basic or Digest authentication                                                                                                                            |                                          | NOT IMPLEMENTED |                                                                                                |
| 3.2.2.  HTTP URIs for Control<br>4.2.  Client Certificate Request Functions                                                                                                                               | EST clients request a certificate from the EST server with an HTTPS POST using the operation path value of "/simpleenroll"                                                                                                                                                                                                                                                                                                                                                                            | MUST                                     | IMPLEMENTED     | test_client_enroll_crt                                                                         |
| 2.3.  Client Certificate Reissuance<br>4.2.2.  Simple Re-enrollment of Clients                                                                                                                            | EST clients request a renew/rekey of existing certificates with an HTTP POST using the operation path value of "/simplereenroll"                                                                                                                                                                                                                                                                                                                                                                      | MUST                                     | IMPLEMENTED     | test_client_renew                                                                              |
| 4.2.3.  Simple Enroll and Re-enroll Response                                                                                                                                                              | The client MUST wait at least the specified "retry-after" time before repeating the same request. The client repeats the initial enrollment request after the appropriate "retry-after" interval has expired                                                                                                                                                                                                                                                                                          | MUST                                     | IMPLEMENTED     | test_enroll_retry_after_header                                                                 |
| 2.4. Server key generation                                                                                                                                                                                | /serverkeygen                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 2.5.  Full PKI Request Messages<br>3.2.2.  HTTP URIs for Control                                                                                                                                          | Generating and parsing Full PKI messages is OPTIONAL<br>/fullcmc                                                                                                                                                                                                                                                                                                                                                                                                                                      | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 2.6.  Certificate Signing Request (CSR) Attributes Request<br>3.1.  Application Layer<br>3.2.2.  HTTP URIs for Control<br>                                                                                | Requesting CSR attributes and parsing the returned list of attributes is OPTIONAL<br>/csrattrs                                                                                                                                                                                                                                                                                                                                                                                                        | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.1.  Application Layer<br>3.2.2.  HTTP URIs for Control<br>3.6.2.  Client Use of Implicit TA Database<br>4.1.2.  CA Certificates Request                                                                 | The client MUST also be able to request CA certificates from the EST server and parse the returned "bag" of certificates using<br>/cacerts.<br>The EST client uses the /cacerts response to establish an Explicit Trust Anchor database for subsequent TLS authentication of the EST server.  EST clients MUST NOT engage in any other protocol exchange until after the /cacerts response has been accepted and a new TLS session has been established (using TLS certificate-based authentication). | MUST                                     | IMPLEMENTED     | test_client_cacerts_invalid_est_ta<br>test_client_cacerts<br>test_client_enroll_invalid_est_ta |
| 4.1.2.  CA Certificates Request                                                                                                                                                                           | Clients SHOULD request an up-to-date response before stored information has expired in order to ensure the EST CA TA database is up to date.                                                                                                                                                                                                                                                                                                                                                          | OPTIONAL                                 | NOT IN SCOPE    | N/A: the owner of this task is the user of this client.                                        |
| 4.1.3  CA Certificates Response                                                                                                                                                                           | If the client disables the Implicit TA database, and if the EST server certificate was verified using an Implicit TA database entry, then the client MUST include the "Trusted CA Indication" extension in future TLS sessions [RFC6066]                                                                                                                                                                                                                                                              | MUST                                     | NOT IMPLEMENTED |                                                                                                |
| 4.1.3  CA Certificates Response                                                                                                                                                                           | The EST server SHOULD include the three "Root CA Key Update" certificates OldWithOld, OldWithNew, and NewWithOld in the response chain. The EST client MUST be able to handle these certificates in the response.                                                                                                                                                                                                                                                                                     | MUST                                     | NOT IMPLEMENTED |                                                                                                |
| 3.1.  Application Layer<br>3.6.1.  Client Use of Explicit TA Database<br>4.1.1.  Bootstrap Distribution of CA Certificates                                                                                | Implementations conforming to this standard MUST provide the ability to designate Explicit Tas                                                                                                                                                                                                                                                                                                                                                                                                        | RECOMMENDED                              | IMPLEMENTED     | test_client_cacerts                                                                            |
| 4.1.3  CA Certificates Response                                                                                                                                                                           | After out-of-band validation occurs, all the other certificates MUST be validated using normal [RFC5280] certificate path validation (using the most recent CA certificate as the TA) before they can be used to build certificate paths during certificate validation.                                                                                                                                                                                                                               | MUST                                     | IMPLEMENTED     | test_client_cacerts_invalid_est_ta<br>test_client_cacerts<br>test_client_enroll_invalid_est_ta |
| 3.1.  Application Layer<br>3.6.1.  Client Use of Explicit TA Database                                                                                                                                     | For human usability reasons, a "fingerprint" of an Explicit TA database entry can be configured for bootstrapping as discussed in Section 4.1.1                                                                                                                                                                                                                                                                                                                                                       | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.1.  Application Layer<br>3.3.1.  TLS-Based Server Authentication<br>3.6.2.  Client Use of Implicit TA Database                                                                                          | Implementations conforming to this standard MUST provide the ability to disable use of any Implicit TA database.<br>The client MUST maintain a distinction between the use of Explicit and Implicit TA databases during authentication in order to support proper authorization                                                                                                                                                                                                                       | MUST                                     | NOT IMPLEMENTED |                                                                                                |
| 4.1.1.  Bootstrap Distribution of CA Certificates                                                                                                                                                         | The client MAY provisionally continue the TLS handshake to completion for the purposes of accessing the /cacerts or /fullcmc method.  If the EST client continues with an unauthenticated connection, the client MUST extract the HTTP content data from the response (Sections 4.1.3 or 4.3.2) and engage a human user to authorize the CA certificate using out-of-band data such as a CA certificate "fingerprint" (e.g., a SHA-256 or SHA-512 [SHS] hash on the whole CA certificate).            | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.1.  Application Layer                                                                                                                                                                                   | the EST client can be configured with a tuple composed of the authority portion of the URI along with the OPTIONAL label (e.g., "www.example.com:80" and "arbitraryLabel1")                                                                                                                                                                                                                                                                                                                           | OPTIONAL                                 | IMPLEMENTED     | test_client_enroll_basic_with_label<br>test_cacerts_ok_with_label                              |
| 3.2.1.  HTTP Headers for Control                                                                                                                                                                          | HTTP redirections (3xx status codes) to the same web origin (see [RFC6454]) SHOULD be handled by the client without user input so long as all applicable security checks                                                                                                                                                                                                                                                                                                                              | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.3.  TLS Layer                                                                                                                                                                                           | HTTPS MUST be used.  TLS 1.1 [RFC4346] (or a later version) MUST be used for all EST communications                                                                                                                                                                                                                                                                                                                                                                                                   | MUST                                     | IMPLEMENTED     | test_client_cacerts                                                                            |
| 3.3.  TLS Layer                                                                                                                                                                                           | TLS session resumption [RFC5077] SHOULD be supported<br>When performing renegotiation, TLS "secure_renegotiation" [RFC5746 MUST be used                                                                                                                                                                                                                                                                                                                                                               | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.3.  TLS Layer<br>3.5.  Linking Identity and POP Information                                                                                                                                             | The client can determine if the server requires the linking of identity and POP by examining the CSR Attributes Response                                                                                                                                                                                                                                                                                                                                                                              | OPTIONAL                                 | NOT IMPLEMENTED |                                                                                                |
| 3.3.  TLS Layer<br>3.5.  Linking Identity and POP Information                                                                                                                                             | Regardless of the CSR Attributes Response, clients SHOULD link identity and POP by embedding tls-unique information in the certification request                                                                                                                                                                                                                                                                                                                                                      | OPTIONAL                                 | IMPLEMENTED     | test_client_enroll_basic_pop                                                                   |


## Build

cmake -Ssrc -Bbuild
cd build
make
./bin/rfc7030-est-client-tests
./bin/rfc7030-est-integration-tests


### Run the tests






## The project
This repository contains some parts of the EST rfc implementation:
- Low level library
- SSL/X.509 Backend agnostic client logic
- Unit tests
- Integration tests
- OpenSSL backend implementation
- Command line blueprint client

### Low level library and SSL/X.509 Backend agnostic client logic
<b>src/lib</b> folder, contins the real EST implementation and a partial implementation for an EST client.

Library is a very low level set of methods prefixed by est_xxx which implements all technical parts of the protocol, for example
est_connect or est_cacert. These functions only implements specific parts of the RFC so its difficoult to use them directly.

In this folder you can find a first level client implementation; this client is agnostic regarding the SSL library used and MUST be used only as a support for the real client. Client functions uses a standard prefix est_client_xxx.

### Unit tests and Integration tests
The two folders <b>src/test</b> and <b>src/integration</b> contains the code used to run all tests. Both produces an executable.

Tests are implemented using a specific backend implemenation so if you want to support a new SSL or X.509 technology you need to implementa test functions also.

Integration tests runs with the http://testrfc7030.com est server so an internet connection is mandatory.

### Command line blueprint client
The folder <b>src/client</b> contains the EST Client reference implementation.

The client supports every backend implementation using build parameters. 

### Dependencies
The client library uses only 1 third parts dependency and is a compile dependency.

You can find the picohttpparser library as a git submodule in the src/third_party folder. No additional dependency are used.

At runtime, the clients needs only a backend library implementation, such as OpenSSL, to run.

## SSL/X.509 Backend
As described before, the EST library (and the client you can find in the src/lib folder) is agnostic about the SSL/X.509 implementation. This provides the freedom to port the code to every platform you want or need.

To support this requirement there are several opaque types that must be implemented using the SSL/X.509 implementation.

You can find the description for every type in the header file as a comment.

### Structure of a backend





