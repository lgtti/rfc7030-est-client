#include "internal.h"

void oss_load_implicit_ta(const char *chain_pem, ESTClient_Options_t *opts)
{
    if (chain_pem == NULL || opts == NULL)
    {
        LOG_ERROR(("Chain or Options is NULL\n"));
        return;
    }
    // Load all certificates in CACHAIN (used to validate EST server https endpoint).
    size_t chain_pem_len = strlen(chain_pem);

    size_t chain_mem_len = 5; // very very large, impossible to have a huge chain like this!
    opts->chain = (ESTCertificate_t **)malloc(sizeof(ESTCertificate_t *) * chain_mem_len);
    if (opts->chain == NULL)
    {
        LOG_ERROR(("Failed to allocate memory for chain\n"));
        return;
    }
    opts->chain_len = 0;

    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (crt == NULL)
    {
        LOG_ERROR(("Failed to allocate memory for crt\n"));
        free(opts->chain);
        return;
    }
    mbedtls_x509_crt_init(crt);

    int ret;
    ret = mbedtls_x509_crt_parse(crt, (const unsigned char *)chain_pem, chain_pem_len + 1);
    if (ret < 0)
    {
        LOG_ERROR(("Failed to parse certificate in chain\n"));
        mbedtls_x509_crt_free(crt);
        oss_print_error(ret);
        free(opts->chain);
        free(crt);
        return;
    }
    
    // the chain crt will be chain as linkedlist in crt.next
    opts->chain[0] = (ESTCertificate_t *)crt;
    opts->chain_len = 1;

    LOG_INFO(("Implicit TA loading completed. Certificate number %d\n", (int)opts->chain_len))
}

void oss_free_implicit_ta(ESTClient_Options_t *opts)
{
    if (opts == NULL || opts->chain == NULL)
    {
        return;
    }
    for(int i = 0; i < opts->chain_len; i++)
    {
        mbedtls_x509_crt *crt = (mbedtls_x509_crt *)opts->chain[i];
        if(crt != NULL)
        {
            mbedtls_x509_crt_free(crt);
            free(crt);
        }
    }
    free(opts->chain);
    opts->chain = NULL;
}

int oss_crt2pem_noterminator(mbedtls_x509_crt *crt, char *pem, size_t pem_len)
{
    if (crt == NULL || pem == NULL || pem_len == 0)
    {
        LOG_ERROR(("Invalid input parameters\n"));
        return EST_FALSE;
    }
    unsigned char buffer[BUFFER_SIZE]; // Temporary buffer for PEM data
    memset(buffer, 0, sizeof(buffer));
    size_t olen = 0;

    int ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                                       crt->raw.p, crt->raw.len,
                                       buffer, sizeof(buffer), &olen);
    if (ret != 0) {
        oss_print_error(ret);
        return EST_FALSE;
    }

    // Ensure the PEM data fits in the provided buffer
    if (olen - 1 > pem_len) {
        LOG_ERROR(("Provided buffer is too small\n"));
        return EST_FALSE;
    }

    // Copy the PEM data to the provided buffer, excluding the null terminator
    memcpy(pem, buffer, olen - 1);

    return olen - 1;
}

char *oss_err_as_string(int err)
{
    char *buf = (char *)calloc(1, 1024);
    if(buf) 
    {
        mbedtls_strerror(err, buf, 1024);
    }
    return buf;
}

void oss_print_error(int err)
{
    char *mbedtls_err = oss_err_as_string(err);
    if(mbedtls_err) {
        LOG_ERROR(("%s\n", mbedtls_err));
        free(mbedtls_err);
    }
}

int convert_pem_to_der(const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen)
{
    if (input == NULL || output == NULL || olen == NULL)
    {
        LOG_ERROR(("Invalid input parameters\n"));
        return EST_ERROR;
    }
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr((const char *) input, "-----BEGIN");
    if (s1 == NULL) {
        LOG_ERROR(("No substring ---BEGIN\n"));
        return EST_ERROR;
    }

    s2 = (unsigned char *) strstr((const char *) input, "-----END");
    if (s2 == NULL) {
        LOG_ERROR(("No substring ---END\n"));
        return EST_ERROR;
    }

    s1 += 10;
    while (s1 < end && *s1 != '-') {
        s1++;
    }
    while (s1 < end && *s1 == '-') {
        s1++;
    }
    if (*s1 == '\r') {
        s1++;
    }
    if (*s1 == '\n') {
        s1++;
    }

    if (s2 <= s1 || s2 > end) {
        return EST_ERROR;
    }

    ret = mbedtls_base64_decode(NULL, 0, &len, (const unsigned char *) s1, s2 - s1);
    if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return ret;
    }

    if (len > *olen) {
        return EST_ERROR;
    }

    if ((ret = mbedtls_base64_decode(output, len, &len, (const unsigned char *) s1,
                                     s2 - s1)) != 0) {
        return ret;
    }

    *olen = len;

    return EST_FALSE;
}