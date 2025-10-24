/*  
 * This file is part of rfc7030-est-client repo, which is licensed under MIT License  
 * See the LICENSE file in the project root for more information.  
 *  
 */

#include "rfc7030.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pkcs7.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509.h>
#include <mbedtls/base64.h>
#include <mbedtls/pem.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/asn1.h>
#include <mbedtls/platform.h>
#include <assert.h>
#include <string.h>

#include <unistd.h>

#define BUFFER_SIZE 4096

#define EST_FEATURE_NOT_SUPPORTED 0x1
#define EST_FEATURE_NOT_IMPLEMENTED 0x2



/**
 * @brief a string representation of the given error code.
 *
 * @param err The error code to convert to a string.
 * @return A pointer to a string representing the error code.
 */
char *oss_err_as_string (int err);

/**
 * @brief Prints an error message to the standard output.
 */
void oss_print_error();

/**
 * @brief Loads the implicit trust anchor from a PEM-encoded certificate chain.
 *
 * This function loads the implicit trust anchor from a PEM-encoded certificate chain
 * and updates the EST client options accordingly.
 *
 * @param chain_pem The PEM-encoded certificate chain.
 * @param opts The EST client options structure.
 */
void oss_load_implicit_ta(const char *chain_pem, ESTClient_Options_t *opts);

/**
 * @brief Frees the memory allocated for the implicit trust anchor in the EST client options.
 *
 * This function frees the memory allocated for the implicit trust anchor in the EST client options structure.
 *
 * @param opts The EST client options structure.
 */
void oss_free_implicit_ta(ESTClient_Options_t *opts);


/**
 * @brief an X.509 certificate to PEM format without adding a null terminator.
 *
 * @param crt       The mbedtls_x509_crt structure representing the certificate.
 * @param pem       The buffer to store the PEM-formatted certificate.
 * @param pem_len   The length of the buffer.
 *
 * @return          0 if successful, or a negative error code if an error occurred.
 */
int oss_crt2pem_noterminator(mbedtls_x509_crt *crt, char *pem, size_t pem_len);

#define EST_ERROR_TLS_SSL_CTX                           0x1
#define EST_ERROR_TLS_STORE_CA_CERT                     0x2
#define EST_ERROR_TLS_CONNECT                           0x3
#define EST_ERROR_TLS_GET_TUNNEL_REF                    0x4
#define EST_ERROR_TLS_START_HANDSHAKE                   0x5
#define EST_ERROR_TLS_SERVERCERT_MISSING                0x6
#define EST_ERROR_TLS_SERVERCERT_INVALID                0x7


/**
 * @brief Generates a unique TLS identifier.
 *
 * This function generates a unique TLS identifier using the provided transport interface.
 *
 * @param tint The transport interface used for generating the identifier.
 * @param output Pointer to the output buffer where the identifier will be stored.
 * @param len Pointer to the length of the output buffer. After the function call, it will contain the actual length of the generated identifier.
 * @param err Pointer to an ESTError_t variable that will store any error occurred during the generation of the identifier.
 *
 * @return Boolean value indicating the success (true) or failure (false) of the operation.
 */
bool_t tls_unique(TransportInterface_t  *tint, char *output, size_t *len, ESTError_t *err);

/**
 * @brief Receives data from the TLS network connection.
 *
 * This function is responsible for receiving data from the TLS network connection
 * specified by the given `pNetworkContext`. The received data is stored in the
 * provided `pBuffer` with a maximum size of `bytesToRecv`.
 *
 * @param pNetworkContext The pointer to the network context structure.
 * @param pBuffer The pointer to the buffer where the received data will be stored.
 * @param bytesToRecv The maximum number of bytes to receive.
 *
 * @return The number of bytes received on success, or a negative error code on failure.
 */
int32_t tls_recv( NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv );


/**
 * @brief data over a TLS connection.
 *
 * This function sends the specified buffer of data over the TLS connection
 * represented by the given network context.
 *
 * @param pNetworkContext Pointer to the network context representing the TLS connection.
 * @param pBuffer Pointer to the buffer containing the data to be sent.
 * @param bytesToSend Number of bytes to send from the buffer.
 *
 * @return Returns the number of bytes sent on success, or a negative error code on failure.
 */
int32_t tls_send( NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend );

/**
 * @brief a TLS connection with the specified parameters.
 *
 * @param host The hostname or IP address of the server.
 * @param tls_host The hostname or IP address to be used for TLS negotiation.
 * @param auth The authentication data to be used for the TLS connection.
 * @param chain An array of ESTCertificate_t pointers representing the certificate chain.
 * @param chain_len The length of the certificate chain array.
 * @param skip_verify Flag indicating whether to skip certificate verification.
 * @param tint The transport interface to be used for the TLS connection.
 * @param err Pointer to an ESTError_t variable to store any error that occurs during initialization.
 * 
 * @return True if the TLS connection was successfully initialized, false otherwise.
 */
bool_t tls_init(const char *host, const char *tls_host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *tint, ESTError_t *err);

/**
 * @brief Frees the resources associated with the TransportInterface_t context.
 *
 * This function releases any resources allocated for the TransportInterface_t context,
 * allowing them to be reused or deallocated. It should be called when the context is
 * no longer needed to prevent memory leaks.
 *
 * @param ctx The TransportInterface_t context to be freed.
 */
void tls_free(TransportInterface_t *ctx);

#define EST_ERROR_X509_PKCS7_PREPARE            0x1
#define EST_ERROR_X509_PKCS7_PARSE              0x2
#define EST_ERROR_X509_PKCS7_NOCERTS_SECTION    0x3
#define EST_ERROR_X509_CERT_PREPARE             0x4
#define EST_ERROR_X509_CERT_PARSE               0x5
#define EST_ERROR_X509_CERT_VERIFY              0x6
#define EST_ERROR_X509_CERT_STORE               0x7
#define EST_ERROR_X509_P12                      0x8
#define EST_ERROR_X509_B64                      0x9
#define EST_ERROR_X509_CERT_SELF_SIGNED         0xA


/**
 * @brief a base64-encoded PKCS7 structure and returns an ESTPKCS7_t object.
 *
 * @param b64 Pointer to the base64-encoded PKCS7 structure.
 * @param b64_bytes_len Length of the base64-encoded PKCS7 structure in bytes.
 * @param err Pointer to an ESTError_t object to store any error that occurs during parsing.
 * 
 * @return Pointer to the parsed ESTPKCS7_t object, or NULL if an error occurs.
 */
ESTPKCS7_t * x509_pkcs7_parse(byte_t *b64, int b64_bytes_len, ESTError_t *err);

/**
 * @brief Frees the memory allocated for an ESTPKCS7_t structure.
 *
 * This function frees the memory allocated for an ESTPKCS7_t structure, which represents
 * a PKCS#7 structure used in X.509 certificate handling.
 *
 * @param output Pointer to the ESTPKCS7_t structure to be freed.
 * @return Boolean value indicating the success of the operation. Returns `true` if the
 *         memory was successfully freed, and `false` otherwise.
 */
bool_t x509_pkcs7_free(ESTPKCS7_t *output);

/**
 * @brief Retrieves the certificates from an ESTPKCS7 structure.
 *
 * This function extracts the certificates from the specified ESTPKCS7 structure and
 * returns them in the output parameter. The certificates are represented as an array
 * of ESTCertificate_t pointers. The number of certificates is determined by the size
 * of the array.
 *
 * @param p7 The ESTPKCS7 structure from which to retrieve the certificates.
 * @param output A pointer to an array of ESTCertificate_t pointers to store the
 *               retrieved certificates.
 * @param err A pointer to an ESTError_t structure to store any error information.
 *
 * @return The number of certificates retrieved, or 0 if an error occurred.
 */
int x509_pkcs7_get_certificates(ESTPKCS7_t *p7, ESTCertificate_t ***output, ESTError_t *err);

/**
 * @brief the first certificate from an ESTPKCS7 structure.
 *
 * This function retrieves the first certificate from the specified ESTPKCS7 structure `p7`.
 * The length of the certificate is returned in the `len` parameter.
 * If an error occurs during the retrieval process, the error code is returned in the `err` parameter.
 *
 * @param p7   The ESTPKCS7 structure from which to retrieve the certificate.
 * @param len  A pointer to a variable that will hold the length of the retrieved certificate.
 * @param err  A pointer to a variable that will hold the error code, if any.
 *
 * @return     A pointer to the retrieved certificate, or NULL if an error occurred.
 */
ESTCertificate_t * x509_pkcs7_get_first_certificate(ESTPKCS7_t *p7, size_t *len, ESTError_t *err);

/**
 * @brief Parses an X.509 certificate from a PEM-encoded byte array.
 *
 * This function takes a PEM-encoded byte array and parses it to extract an X.509 certificate.
 *
 * @param pem Pointer to the PEM-encoded byte array.
 * @param pem_bytes_len Length of the PEM-encoded byte array.
 * @param err Pointer to an ESTError_t variable to store any error that occurs during parsing.
 *
 * @return A pointer to the parsed ESTCertificate_t structure, or NULL if an error occurs.
 */
ESTCertificate_t * x509_certificate_parse(byte_t *pem, int pem_bytes_len, ESTError_t *err);

/**
 * @brief the memory allocated for an X.509 certificate.
 *
 * @param cert The pointer to the ESTCertificate_t structure representing the certificate.
 * @return True if the certificate was successfully freed, false otherwise.
 */
bool_t x509_certificate_free(ESTCertificate_t *cert);

/**
 * @brief if an X.509 certificate is self-signed.
 *
 * This function takes an X.509 certificate and determines whether it is self-signed or not.
 *
 * @param certificate The X.509 certificate to be checked.
 * @param result A pointer to a boolean variable where the result will be stored.
 *               If the certificate is self-signed, the variable will be set to true.
 *               If the certificate is not self-signed, the variable will be set to false.
 * @param err A pointer to an ESTError_t variable where any error encountered during the operation will be stored.
 *            If no error occurs, the variable will be set to EST_ERR_NONE.
 *
 * @return A boolean value indicating whether the operation was successful or not.
 *         Returns true if the operation was successful, false otherwise.
 */
bool_t x509_certificate_is_self_signed(ESTCertificate_t *certificate, bool_t *result, ESTError_t *err);

/**
 * @brief the X.509 certificate chain.
 *
 * This function verifies the X.509 certificate chain using the provided root certificate store,
 * the intermediate certificates, and the end-entity certificate. The result of the verification
 * is stored in the `result` parameter. If the verification fails, an error code is returned in
 * the `err` parameter.
 *
 * @param root The root certificate store.
 * @param sub The array of intermediate certificates.
 * @param sub_len The number of intermediate certificates in the array.
 * @param certificate The end-entity certificate to be verified.
 * @param result Pointer to a boolean variable to store the verification result.
 * @param err Pointer to an `ESTError_t` variable to store the error code, if any.
 * @return `true` if the verification is successful, `false` otherwise.
 */
bool_t x509_certificate_verify(ESTCertificateStore_t *root, ESTCertificate_t **sub, size_t sub_len, ESTCertificate_t *certificate, bool_t *result, ESTError_t *err);

/**
 * @brief Creates a new ESTCertificateStore_t object.
 *
 * This function creates a new ESTCertificateStore_t object and returns a pointer to it.
 * The ESTCertificateStore_t object is used to store X.509 certificates for the EST protocol.
 *
 * @param err Pointer to an ESTError_t object to store any error that occurs during the creation of the certificate store.
 *
 * @return Pointer to the newly created ESTCertificateStore_t object, or NULL if an error occurred.
 */
ESTCertificateStore_t * x509_certificate_store_create(ESTError_t *err);

/**
 * @brief Frees the memory allocated for an X.509 certificate store.
 *
 * This function frees the memory allocated for an X.509 certificate store
 * and sets the pointer to NULL.
 *
 * @param store A pointer to the X.509 certificate store to be freed.
 */
void x509_certificate_store_free(ESTCertificateStore_t **store);

/**
 * @brief a certificate to the X.509 certificate store.
 *
 * @param store The ESTCertificateStore_t object representing the certificate store.
 * @param certificate The ESTCertificate_t object representing the certificate to be added.
 * @param err Pointer to an ESTError_t object to store any error that occurs during the operation.
 * 
 * @return Boolean value indicating whether the certificate was successfully added to the store.
 */
bool_t x509_certificate_store_add(ESTCertificateStore_t *store, ESTCertificate_t *certificate, ESTError_t *err);

/**
 * @brief Parses a PKCS#7 DER-encoded data structure.
 *
 * This function parses a PKCS#7 DER-encoded data structure and populates the
 * provided `pkcs7` structure with the parsed data.
 *
 * @param pkcs7 The mbedtls_pkcs7 structure to populate with the parsed data.
 * @param buf   The buffer containing the DER-encoded data.
 * @param buflen The length of the buffer.
 *
 * @return 0 if successful, or a negative error code if an error occurred.
 */
int pkcs7_parse_der(mbedtls_pkcs7 *pkcs7, char *buf, const size_t buflen);
int pkcs7_get_signed_data(unsigned char *buf, size_t buflen, mbedtls_pkcs7_signed_data *signed_data);
static int pkcs7_get_certificates(unsigned char **p, unsigned char *end, mbedtls_x509_crt *certs);
static int pkcs7_get_content_info_type(unsigned char **p, unsigned char *end, unsigned char **seq_end, mbedtls_pkcs7_buf *pkcs7);
static int pkcs7_get_version(unsigned char **p, unsigned char *end, int *ver);
static int pkcs7_get_signers_info_set(unsigned char **p, unsigned char *end, mbedtls_pkcs7_signer_info *signers_set, mbedtls_x509_buf *digest_alg);
static int pkcs7_get_signer_info(unsigned char **p, unsigned char *end, mbedtls_pkcs7_signer_info *signer, mbedtls_x509_buf *alg);                                      
static int pkcs7_get_digest_algorithm_set(unsigned char **p, unsigned char *end, mbedtls_x509_buf *alg);
static void pkcs7_free_signer_info(mbedtls_pkcs7_signer_info *signer);
static int pkcs7_get_signature(unsigned char **p, unsigned char *end,mbedtls_pkcs7_buf *signature);
static int pkcs7_get_digest_algorithm(unsigned char **p, unsigned char *end, mbedtls_x509_buf *alg);

/**
 * @brief a PEM-encoded data to DER format.
 *
 * This function takes a PEM-encoded data as input and converts it to DER format.
 * The input data is provided as a pointer to `input` and its length is specified
 * by `ilen`. The converted DER data is written to the buffer pointed by `output`,
 * and the length of the converted data is stored in `olen`.
 *
 * @param input  Pointer to the PEM-encoded data.
 * @param ilen   Length of the input data.
 * @param output Pointer to the buffer to store the converted DER data.
 * @param olen   Pointer to the variable to store the length of the converted data.
 *
 * @return 0 if the conversion is successful, or a negative error code if an error occurs.
 */
int convert_pem_to_der(const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen);

/**
 * @brief (FEATURE NOT IMPLEMENTED) Parses a P12 file and extracts authentication data. 
 * 
 * This function takes a P12 file, along with its length, a password, and pointers to
 * `ESTAuthData_t` and `ESTError_t` structures. It parses the P12 file, extracts the
 * authentication data, and stores it in the `ESTAuthData_t` structure. Any errors
 * encountered during the parsing process are stored in the `ESTError_t` structure.
 *
 * @param p12 The P12 file data.
 * @param p12_len The length of the P12 file data.
 * @param password The password to decrypt the P12 file.
 * @param auth Pointer to the `ESTAuthData_t` structure to store the authentication data.
 * @param err Pointer to the `ESTError_t` structure to store any encountered errors.
 * @return `true` if the P12 file was successfully parsed and authentication data was extracted,
 *         `false` otherwise.
 */
bool_t parse_p12(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err);

/**
 * @brief a CSR (Certificate Signing Request) from the given context.
 *
 * @param ctx The context to load the CSR from.
 * @param tlsunique The TLS unique identifier.
 * @param tlsunique_len The length of the TLS unique identifier.
 * @param csr The buffer to store the loaded CSR.
 * @param csr_len On input, the size of the buffer. On output, the actual length of the loaded CSR.
 * @param err Pointer to an ESTError_t variable to store any error that occurs during the loading process.
 * @return True if the CSR was successfully loaded, false otherwise.
 */
static bool_t load_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err);

/**
 * @brief  (FEATURE NOT IMPLEMENTED)
 * Parses a basic authentication string and extracts authentication data.
 *
 * @param userpassword The basic authentication string.
 * @param auth Pointer to the `ESTAuthData_t` structure to store the authentication data.
 * @param err Pointer to the `ESTError_t` structure to store any encountered errors.
 * @return True if the basic authentication string was successfully parsed and authentication data was extracted,
 *         false otherwise.
 */
bool_t parse_basicauth(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err);
