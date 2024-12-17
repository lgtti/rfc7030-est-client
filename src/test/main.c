#include "munit.h"
#include <stdlib.h>
#include <stdio.h>

#include "rfc7030.h"

#ifndef TEST_RESOURCE_FOLDER 
#define TEST_RESOURCE_FOLDER "res"
#endif

ESTCertificate_t * pf2crt(const char *name);
ESTCertificate_t * pem2crt(const char *pem);
bool_t crt_equals(ESTCertificate_t *received, ESTCertificate_t *expected);
bool_t is_issuer(ESTCertificate_t *issuer, ESTCertificate_t *crt);

typedef struct TestNetworkContext {
    size_t tls_recv_idx;
    const char **tls_recv;
}TestNetworkContext_t;

static char *cacerts_tls_recv[] = {
    // cacerts response
    "HTTP/1.1 200 OK\n"
    "Status: 200 OK\n"
    "Content-Type: application/pkcs7-mime\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Length: 533\n"
    "\n"
    "MIIBgwYJKoZIhvcNAQcCoIIBdDCCAXACAQExADALBgkqhkiG9w0BBwGgggFYMIIB\n"
    "VDCB+qADAgECAgkAq+gy4fZqa0MwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMZXN0\n"
    "RXhhbXBsZUNBMB4XDTIxMDkwMTE4MjE0MFoXDTMxMDgzMDE4MjE0MFowFzEVMBMG\n"
    "A1UEAxMMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJrLC\n"
    "3kdCWjorNfjmVw6ERgVt5wtFAW0CdlP11PvxrGEHTwsBEXGI7By1JzkFTnAVe/dU\n"
    "gWT0QC5VLrgiUw+XJaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUGt85hMJW\n"
    "5mzPKrQmpf0M0kP1PT4wCgYIKoZIzj0EAwIDSQAwRgIhAJP0XbZh/gtmeahqnIGP\n"
    "BEFv4e8ZADMUYqCl3dywKqiJAiEAoZA5SzJmg/IEmrledlPbAOb/xkeLq3slqsKt\n"
    "sgutA7wxAA==\n",

    // stop execution, no data to return
    "",
};

static char *cacerts_verify_tls_recv[] = {
    //cacerts response part1
    "HTTP/1.1 200 OK\n"
    "Status: 200 OK\n"
    "Content-Type: application/pkcs7-mime\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Length: 3375\n"
    "\n"
    "MIIJuwYJKoZIhvcNAQcCoIIJrDCCCagCAQExADALBgkqhkiG9w0BBwGgggmQMIIDIzCCAsig\n"
    "AwIBAgIUGHp4seOyURqAFYhenEIynJvHiE8wCgYIKoZIzj0EAwIwWTELMAkGA1UEBhMCSVQx\n"
    "GTAXBgNVBAoMEElvVCBJbmZvQ2VydCBTcEExFDASBgNVBAUTCzA3OTQ1MjExMDA2MRkwFwYD\n"
    "VQQDDBBJb1QgU0hBUkVEIEVDRFNBMB4XDTIzMDEyNDE3MzIzMloXDTM4MDEyNDE3MzIzMlow\n"
    "ZzELMAkGA1UEBhMCSVQxGTAXBgNVBAoMEElvVCBJbmZvQ2VydCBTcEExFDASBgNVBAUTCzA3\n"
    "OTQ1MjExMDA2MScwJQYDVQQDDB5Jb1QgU0hBUkVEIERldmljZSBUZXNtZWMgRUNEU0EwWTAT\n"
    "BgcqhkjOPQIBBggqhkjOPQMBBwNCAATlHDPXiXVuQJBDKPz2HjO2W6BPhNqnrsyWkpv+I58R\n"
    "x22sR4648grJYO5vovkT0gMkBXdfmnzCp+sD1jSkzEDyo4IBXjCCAVowEgYDVR0TAQH/BAgw\n"
    "BgEB/wIBADAUBgNVHSAEDTALMAkGBysGAQQCAgEwgZMGCCsGAQUFBwEBBIGGMIGDMDMGCCsG\n"
    "AQUFBzABhidodHRwOi8vaW90LW9jc3AuaW5mb2NlcnQuZGlnaXRhbC9zaGFyZWQwTAYIKwYB\n"
    "BQUHMAKGQGh0dHA6Ly9pb3QuaW5mb2NlcnQuZGlnaXRhbC9jYS9zaGFyZWQvZWNkc2EvSW9U\n",

    //cacerts response part2
    "X1NIQVJFRF9FQ0RTQS5jcnQwSAYDVR0fBEEwPzA9oDugOYY3aHR0cDovL2lvdC5pbmZvY2Vy\n"
    "dC5kaWdpdGFsL2NybC9zaGFyZWQvZWNkc2EvY2EvQ1JMLmNybDAOBgNVHQ8BAf8EBAMCAQYw\n"
    "HQYDVR0OBBYEFK9trA2QbnG/NgfVmWT4o+FHvRPkMB8GA1UdIwQYMBaAFFKSdZfOkpZtQqU5\n"
    "x3WpJMLwAyxvMAoGCCqGSM49BAMCA0kAMEYCIQCtaHFm8yu45g3/WtIh/ON7ISs0zgvMa38K\n"
    "Cu8g0X1w8gIhAJe8TIn4tGgh0TpXfRQsJIBRsxpvC/4Vs1UhaK+dkEy+MIIC4zCCAomgAwIB\n"
    "AgIUJqKbEpSMtD6QGzZ8wMqSUIN5UjkwCgYIKoZIzj0EAwIwVTELMAkGA1UEBhMCSVQxGTAX\n"
    "BgNVBAoMEElvVCBJbmZvQ2VydCBTcEExFDASBgNVBAUTCzA3OTQ1MjExMDA2MRUwEwYDVQQD\n"
    "DAxTUyBJb1QgRUNEU0EwIBcNMjMwMTIzMTYwMTQxWhgPMjA1ODAxMjMxNzAxNDFaMFUxCzAJ\n"
    "BgNVBAYTAklUMRkwFwYDVQQKDBBJb1QgSW5mb0NlcnQgU3BBMRQwEgYDVQQFEwswNzk0NTIx\n"
    "MTAwNjEVMBMGA1UEAwwMU1MgSW9UIEVDRFNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n",

    //cacerts response part3
    "CwrwSnCOWlMlldkpd4jPAQ9jKi/uDjx9UXgD6cCCwTihkD8m32ypL9cd/DCQeG/cT5Eod7Om\n"
    "ajnhTzCNORHQG6OCATMwggEvMA8GA1UdEwEB/wQFMAMBAf8wgYoGCCsGAQUFBwEBBH4wfDAs\n"
    "BggrBgEFBQcwAYYgaHR0cDovL2lvdC1vY3NwLmluZm9jZXJ0LmRpZ2l0YWwwTAYIKwYBBQUH\n"
    "MAKGQGh0dHA6Ly9pb3QuaW5mb2NlcnQuZGlnaXRhbC9jYS9zZWxmc2lnbmVkL2VjZHNhL1NT\n"
    "X0lvVF9FQ0RTQS5jcnQwEgYDVR0gBAswCTAHBgUrBgEEAjBMBgNVHR8ERTBDMEGgP6A9hjto\n"
    "dHRwOi8vaW90LmluZm9jZXJ0LmRpZ2l0YWwvY3JsL3NlbGZzaWduZWQvZWNkc2EvY2EvQ1JM\n"
    "LmNybDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNRpUVlZfiFynkPiuProhZrst02CMAoG\n"
    "CCqGSM49BAMCA0gAMEUCIQC8jPcmBcUpuSpRqWxi6vH/Iy8PbZsFMQOUgolQzR5CXgIgaC8N\n"
    "zOgOtFl3dZ2PzP5Splz1IRN1LzqYKoqawDRuANIwggN+MIIDJKADAgECAhRwEC5QlBT1pLhT\n"
    "q0Bj1t+PbsUg1jAKBggqhkjOPQQDAjBVMQswCQYDVQQGEwJJVDEZMBcGA1UECgwQSW9UIElu\n"
    "Zm9DZXJ0IFNwQTEUMBIGA1UEBRMLMDc5NDUyMTEwMDYxFTATBgNVBAMMDFNTIElvVCBFQ0RT\n",

    //cacerts response part4
    "QTAeFw0yMzAxMjQxMjE2MzZaFw00ODAxMjQxMjE2MzZaMFkxCzAJBgNVBAYTAklUMRkwFwYD\n"
    "VQQKDBBJb1QgSW5mb0NlcnQgU3BBMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEZMBcGA1UEAwwQ\n"
    "SW9UIFNIQVJFRCBFQ0RTQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM0v2YCnuB3rRO9M\n"
    "9xhtRejb9nl3OWYi5uZ2g26GZ3ci9y1qPPVd1KlyQ4zMnW0AF7pCwbWxj1Hcv5/Vi5wRmbmj\n"
    "ggHMMIIByDCBigYIKwYBBQUHAQEEfjB8MCwGCCsGAQUFBzABhiBodHRwOi8vaW90LW9jc3Au\n"
    "aW5mb2NlcnQuZGlnaXRhbDBMBggrBgEFBQcwAoZAaHR0cDovL2lvdC5pbmZvY2VydC5kaWdp\n"
    "dGFsL2NhL3NlbGZzaWduZWQvZWNkc2EvU1NfSW9UX0VDRFNBLmNydDASBgNVHRMBAf8ECDAG\n"
    "AQH/AgEBMBMGA1UdIAQMMAowCAYGKwYBBAICMEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9p\n"
    "b3QuaW5mb2NlcnQuZGlnaXRhbC9jcmwvc2VsZnNpZ25lZC9lY2RzYS9jYS9DUkwuY3JsMA4G\n"
    "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUUpJ1l86Slm1CpTnHdakkwvADLG8wgZIGA1UdIwSB\n"
    "ijCBh4AU1GlRWVl+IXKeQ+K4+uiFmuy3TYKhWaRXMFUxCzAJBgNVBAYTAklUMRkwFwYDVQQK\n"
    "DBBJb1QgSW5mb0NlcnQgU3BBMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEVMBMGA1UEAwwMU1Mg\n"
    "SW9UIEVDRFNBghQmopsSlIy0PpAbNnzAypJQg3lSOTAKBggqhkjOPQQDAgNIADBFAiBb5Tl2\n"
    "WUQy8z4edtkLA8J43e5nd2bLZ+cf+cYE7CoZqQIhAP7UH0AhxwUHIt7HfkiY9+FLEjt3qYjK\n"
    "NvH394j4LHljMQA=\n",

    // stop execution, no data to return
    "",
};

static char *cacerts_failed_verify_tls_recv[] = {
    // cacerts response
    "HTTP/1.1 200 OK\n"
    "Content-Type: application/pkcs7-mime\n"
    "Content-Length: 1952\n"
    "Connection: close\n"
    "X-est-tenant-b64: SW5mb0NlcnQtTEcy\n"
    "X-est-tenant-decoded: InfoCert-LG2\n"
    "X-est-tenant-value: InfoCert\n"
    "X-est-tenant-project: LG2\n"
    "Date: Fri, 19 May 2023 15:50:37 GMT\n"
    "content-transfer-encoding: base64\n"
    "Access-Control-Allow-Origin: *\n"
    "X-Kong-Upstream-Latency: 236\n"
    "X-Kong-Proxy-Latency: 30\n"
    "\n"
    "MIIFsgYJKoZIhvcNAQcCoIIFozCCBZ8CAQExADALBgkqhkiG9w0BBwGgggWHMIIDcTCCAxag"
    "AwIBAgIUTf4GeH6IMtRSZfOz7bxelWar1vgwCgYIKoZIzj0EAwIwbDELMAkGA1UEBhMCSVQx"
    "HzAdBgNVBAoMFkluZnJhc3RydWN0dXJlIE5ldHdvcmsxFDASBgNVBAUTCzEzMTExOTYxMDAy"
    "MSYwJAYDVQQDDB1JbmZyYXN0cnVjdHVyZSBOZXR3b3JrIDI1NiBDQTAeFw0yMjA1MjQxNTE2"
    "MDNaFw0zNzA1MjQxNjE2MDNaMGQxCzAJBgNVBAYTAklUMR8wHQYDVQQKDBZJbmZyYXN0cnVj"
    "dHVyZSBOZXR3b3JrMRQwEgYDVQQFEwsxMzExMTk2MTAwMjEeMBwGA1UEAwwVQ0NJIERldmlj"
    "ZXMgU0hBMjU2IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF3LbaF2O2L7TfiX0Iq72"
    "sJtQv7P7y7MrBd1PWw6eqs9PuBLTuHeelanar0eYrglg1V2E6QPtSD6M+fsggqty8qOCAZww"
    "ggGYMBIGA1UdEwEB/wQIMAYBAf8CAQAwfAYIKwYBBQUHAQEEcDBuMC0GCCsGAQUFBzABhiFo"
    "dHRwOi8vb2NzcC5yb290LmdsaW4uaW5mb2NlcnQuaXQwPQYIKwYBBQUHMAKGMWh0dHA6Ly9j"
    "ZXJ0LmNhLmdsaW4uaW5mb2NlcnQuaXQvY2Evcm9vdDI1Ni9DQS5jcnQwFgYDVR0gBA8wDTAL"
    "BgkrBgEEAbEZeAMwgZsGA1UdHwSBkzCBkDCBjaCBiqCBh4aBhGxkYXA6Ly9sZGFwLmNhLmds"
    "aW4uaW5mb2NlcnQuaXQvY24lM0RJbmZyYXN0cnVjdHVyZSUyME5ldHdvcmslMjAyNTYlMjBD"
    "QSxvJTNESW5mcmFzdHJ1Y3R1cmUlMjBOZXR3b3JrLGMlM0RJVD9hdXRob3JpdHlSZXZvY2F0"
    "aW9uTGlzdDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA4QsqN23/MMwiqaa64ulgLA3llX"
    "MB8GA1UdIwQYMBaAFAHwQ1vs7hHFT4CA0ke9bN+g8mRoMAoGCCqGSM49BAMCA0kAMEYCIQDn"
    "2shPUEOIyuWbFWzHp2MyYp33IqDMttaerWo6WyzOCgIhAIXfSO7FbocxvxmCEGwHbr8SVbvJ"
    "ETfZJhwsz5v/+ANEMIICDjCCAbSgAwIBAgIUALlgTbFTONKEFDwHjBj3rO7XOS8wCgYIKoZI"
    "zj0EAwIwZDELMAkGA1UEBhMCSVQxGTAXBgNVBAoMEElvVCBJbmZvQ2VydCBTcEExFDASBgNV"
    "BAUTCzA3OTQ1MjExMDA2MSQwIgYDVQQDDBtJbmZvQ2VydCBNSURQS0kgUm9vdCAyNTYgQ0Ew"
    "IBcNMjIwNTI0MTQyMDE1WhgPMjA1NzA1MjQxNTIwMTVaMGQxCzAJBgNVBAYTAklUMRkwFwYD"
    "VQQKDBBJb1QgSW5mb0NlcnQgU3BBMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEkMCIGA1UEAwwb"
    "SW5mb0NlcnQgTUlEUEtJIFJvb3QgMjU2IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
    "wEmvY07CnLeyYFol1977LS0IedgZURPWi/lWCu2LOJ0Jw8TAvEPwN+oCAiC5JOmq2GAr+M1X"
    "+f8LvJJBkPSsGaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O"
    "BBYEFOB6mwYsYDVuk1TNQaNqQeFOzb8QMAoGCCqGSM49BAMCA0gAMEUCID3sPyu6qDtTgYGy"
    "lthfoxXuGiKwKe0uSMoZUtHNKOdvAiEAuALqMtVV60f6k+BYpRhONvYZUr7o8xphurpKb442"
    "fMExAA==\n",

    // stop execution, no data to return
    "",
};

static char *cacerts_badp7_tls_recv[] = {
    // cacerts response
    "HTTP/1.1 200 OK\n"
    "Content-Type: application/pkcs7-mime\n"
    "Content-Length: 1500\n"
    "Connection: close\n"
    "X-est-tenant-b64: SW5mb0NlcnQtTEcy\n"
    "X-est-tenant-decoded: InfoCert-LG2\n"
    "X-est-tenant-value: InfoCert\n"
    "X-est-tenant-project: LG2\n"
    "Date: Fri, 19 May 2023 15:50:37 GMT\n"
    "content-transfer-encoding: base64\n"
    "Access-Control-Allow-Origin: *\n"
    "X-Kong-Upstream-Latency: 236\n"
    "X-Kong-Proxy-Latency: 30\n"
    "\n"
    "MIIFsgYJKoZIhvcNAQcCoIIFozCCBZ8CAQExADALBgkqhkiG9w0BBwGgggWHMIIDcTCCAxag"
    "AwIBAgIUTf4GeH6IMtRSZfOz7bxelWar1vgwCgYIKoZIzj0EAwIwbDELMAkGA1UEBhMCSVQx"
    "HzAdBgNVBAoMFkluZnJhc3RydWN0dXJlIE5ldHdvcmsxFDASBgNVBAUTCzEzMTExOTYxMDAy"
    "MSYwJAYDVQQDDB1JbmZyYXN0cnVjdHVyZSBOZXR3b3JrIDI1NiBDQTAeFw0yMjA1MjQxNTE2"
    "MDNaFw0zNzA1MjQxNjE2MDNaMGQxCzAJBgNVBAYTAklUMR8wHQYDVQQKDBZJbmZyYXN0cnVj"
    "dHVyZSBOZXR3b3JrMRQwEgYDVQQFEwsxMzExMTk2MTAwMjEeMBwGA1UEAwwVQ0NJIERldmlj"
    "ZXMgU0hBMjU2IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF3LbaF2O2L7TfiX0Iq72"
    "sJtQv7P7y7MrBd1PWw6eqs9PuBLTuHeelanar0eYrglg1V2E6QPtSD6M+fsggqty8qOCAZww"
    "ggGYMBIGA1UdEwEB/wQIMAYBAf8CAQAwfAYIKwYBBQUHAQEEcDBuMC0GCCsGAQUFBzABhiFo"
    "dHRwOi8vb2NzcC5yb290LmdsaW4uaW5mb2NlcnQuaXQwPQYIKwYBBQUHMAKGMWh0dHA6Ly9j"
    "ZXJ0LmNhLmdsaW4uaW5mb2NlcnQuaXQvY2Evcm9vdDI1Ni9DQS5jcnQwFgYDVR0gBA8wDTAL"
    "BgkrBgEEAbEZeAMwgZsGA1UdHwSBkzCBkDCBjaCBiqCBh4aBhGxkYXA6Ly9sZGFwLmNhLmds"
    "aW4uaW5mb2NlcnQuaXQvY24lM0RJbmZyYXN0cnVjdHVyZSUyME5ldHdvcmslMjAyNTYlMjBD"
    "QSxvJTNESW5mcmFzdHJ1Y3R1cmUlMjBOZXR3b3JrLGMlM0RJVD9hdXRob3JpdHlSZXZvY2F0"
    "aW9uTGlzdDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA4QsqN23/MMwiqaa64ulgLA3llX"
    "MB8GA1UdIwQYMBaAFAHwQ1vs7hHFT4CA0ke9bN+g8mRoMAoGCCqGSM49BAMCA0kAMEYCIQDn"
    "2shPUEOIyuWbFWzHp2MyYp33IqDMttaerWo6WyzOCgIhAIXfSO7FbocxvxmCEGwHbr8SVbvJ"
    "ETfZJhwsz5v/+ANEMIICDjCCAbSgAwIBAgIUALlgTbFTONKEFDwHjBj3rO7XOS8wCgYIKoZI"
    "zj0EAwIwZDELMAkGA1UEBhMCSVQxGTAXBgNVBAoMEElvVCBJbmZvQ2VydCBTcEExFDASBgNV"
    "BAUTCzA3OTQ1MjExMDA2MSQwIgYDVQQDDBtJbmZvQ2VydCBNSURQS0kgUm9vdCAyNTYgQ0Ew"
    "IBcNMjIwNTI0MTQyMDE1WhgPMjA1NzA1MjQxNTIwMTVaMGQxCzAJBgNVBAYTAklUMRkwFwYD"
    "VQQKDBBJb1QgSW5mb0NlcnQgU3BBMRQwEgYDVQQFEwswNzk0NTIxMTAwNjEkMCIGA1UEAwwb"
    "SW5mb0NlcnQgTUlEUEtJIFJvb3QgMjU2IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
    "wEmvY07CnLeyYFol1977LS0IedgZURPWi/lWCu2LOJ0Jw8TAvEPwN+oCAiC5JOmq2GAr+M1X"
    "+f8LvJJBkPSsGaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O"
    "BBYEFOB6mwYsYDVuk1TNQaNqQeFOzb8QMAoGCCqGSM49BAMCA0gAMEUCID3sPyu6qDtTgYGy"
    "fMExAA==\n",

    // stop execution, no data to return
    "",
};

static char *enroll_tls_recv[] = {
    "HTTP/1.1 200 OK\n"
    "Status: 200 OK\n"
    "Content-Type: application/pkcs7-mime; smime-type=certs-only\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Length: 581\n"
    "\n"
    "MIIBqQYJKoZIhvcNAQcCoIIBmjCCAZYCAQExADALBgkqhkiG9w0BBwGgggF+MIIB\n"
    "ejCCASCgAwIBAgIDB0sJMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDGVzdEV4YW1w\n"
    "bGVDQTAeFw0yMzA1MjQwNzMwMjZaFw0yNDA1MjMwNzMwMjZaMBgxFjAUBgNVBAMM\n"
    "DUVzdENsaWVudFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS3nPtObhS\n"
    "mR5zV/kcFuIx8kqf1jcD/dCpMdlPhNsSDg3xGG7uQ8N70b31TR6KgJ8wXNQIfqUX\n"
    "PVn0ljxJlMX6o1owWDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQU\n"
    "iGJ2WUzetWjpJt1YYtfWQlL8cj4wHwYDVR0jBBgwFoAUGt85hMJW5mzPKrQmpf0M\n"
    "0kP1PT4wCgYIKoZIzj0EAwIDSAAwRQIgGDzmTOGsj8bI9gdg9lsYhaGZNsUptOXX\n"
    "Iyr/2/+drqgCIQDDVxeoQyFqMxnvaVwZKR1SzcoXpTofkyYHPBlz0f6xKzEA\n",

    //end
    ""
};

static char *enroll_retry_after_tls_recv[] = {
    "HTTP/1.1 202 OK\n"
    "Status: 202 OK\n"
    "Retry-After: 200\n"
    "Content-Type: application/pkcs7-mime; smime-type=certs-only\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Length: 581\n"
    "\n"
    "MIIBqQYJKoZIhvcNAQcCoIIBmjCCAZYCAQExADALBgkqhkiG9w0BBwGgggF+MIIB\n"
    "ejCCASCgAwIBAgIDB0sJMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDGVzdEV4YW1w\n"
    "bGVDQTAeFw0yMzA1MjQwNzMwMjZaFw0yNDA1MjMwNzMwMjZaMBgxFjAUBgNVBAMM\n"
    "DUVzdENsaWVudFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS3nPtObhS\n"
    "mR5zV/kcFuIx8kqf1jcD/dCpMdlPhNsSDg3xGG7uQ8N70b31TR6KgJ8wXNQIfqUX\n"
    "PVn0ljxJlMX6o1owWDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQU\n"
    "iGJ2WUzetWjpJt1YYtfWQlL8cj4wHwYDVR0jBBgwFoAUGt85hMJW5mzPKrQmpf0M\n"
    "0kP1PT4wCgYIKoZIzj0EAwIDSAAwRQIgGDzmTOGsj8bI9gdg9lsYhaGZNsUptOXX\n"
    "Iyr/2/+drqgCIQDDVxeoQyFqMxnvaVwZKR1SzcoXpTofkyYHPBlz0f6xKzEA\n",

    //end
    ""
};

static char *enroll_missing_header_tls_recv[] = {
    "HTTP/1.1 202 OK\n"
    "Status: 202 OK\n"
    "Content-Type: application/pkcs7-mime; smime-type=certs-only\n"
    "Content-Length: 581\n"
    "\n"
    "MIIBqQYJKoZIhvcNAQcCoIIBmjCCAZYCAQExADALBgkqhkiG9w0BBwGgggF+MIIB\n"
    "ejCCASCgAwIBAgIDB0sJMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDGVzdEV4YW1w\n"
    "bGVDQTAeFw0yMzA1MjQwNzMwMjZaFw0yNDA1MjMwNzMwMjZaMBgxFjAUBgNVBAMM\n"
    "DUVzdENsaWVudFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS3nPtObhS\n"
    "mR5zV/kcFuIx8kqf1jcD/dCpMdlPhNsSDg3xGG7uQ8N70b31TR6KgJ8wXNQIfqUX\n"
    "PVn0ljxJlMX6o1owWDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQU\n"
    "iGJ2WUzetWjpJt1YYtfWQlL8cj4wHwYDVR0jBBgwFoAUGt85hMJW5mzPKrQmpf0M\n"
    "0kP1PT4wCgYIKoZIzj0EAwIDSAAwRQIgGDzmTOGsj8bI9gdg9lsYhaGZNsUptOXX\n"
    "Iyr/2/+drqgCIQDDVxeoQyFqMxnvaVwZKR1SzcoXpTofkyYHPBlz0f6xKzEA\n",

    //end
    ""
};

static char *enroll_invalid_smime_tls_recv[] = {
    "HTTP/1.1 202 OK\n"
    "Status: 202 OK\n"
    "Content-Type: application/pkcs7-mime\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Length: 581\n"
    "\n"
    "MIIBqQYJKoZIhvcNAQcCoIIBmjCCAZYCAQExADALBgkqhkiG9w0BBwGgggF+MIIB\n"
    "ejCCASCgAwIBAgIDB0sJMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDGVzdEV4YW1w\n"
    "bGVDQTAeFw0yMzA1MjQwNzMwMjZaFw0yNDA1MjMwNzMwMjZaMBgxFjAUBgNVBAMM\n"
    "DUVzdENsaWVudFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQS3nPtObhS\n"
    "mR5zV/kcFuIx8kqf1jcD/dCpMdlPhNsSDg3xGG7uQ8N70b31TR6KgJ8wXNQIfqUX\n"
    "PVn0ljxJlMX6o1owWDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQU\n"
    "iGJ2WUzetWjpJt1YYtfWQlL8cj4wHwYDVR0jBBgwFoAUGt85hMJW5mzPKrQmpf0M\n"
    "0kP1PT4wCgYIKoZIzj0EAwIDSAAwRQIgGDzmTOGsj8bI9gdg9lsYhaGZNsUptOXX\n"
    "Iyr/2/+drqgCIQDDVxeoQyFqMxnvaVwZKR1SzcoXpTofkyYHPBlz0f6xKzEA\n",

    //end
    ""
};

typedef struct TestMockConfig {
    bool_t test_tls_initialize_return_code;
    TransportInterface_t test_tls_ctx;
}TestMockConfig_t;

typedef struct TestCertificate {
    char name[10];
}TestCertificate_t;

static TestMockConfig_t mock_config;

static TestCertificate_t cachain[] = {
    { .name = "unused" }
};

static ESTError_t err;

static ESTAuthData_t auth = {
    .type = EST_AUTH_TYPE_NONE
};

static ESTClient_Options_t opts = {
    .chain = (ESTCertificate_t **)&cachain,
    .chain_len = sizeof(cachain),
    .strict8951 = EST_TRUE,
};

static int32_t test_tls_recv( NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv ) {
    TestNetworkContext_t *net_ctx = (TestNetworkContext_t *)pNetworkContext;
    int32_t recv_bytes = -1;

    if(net_ctx->tls_recv_idx >= 0) { 
        const char *tosend = net_ctx->tls_recv[net_ctx->tls_recv_idx];

        if(strlen(tosend) > 0) {
            memcpy(pBuffer, tosend, strlen(tosend));
            net_ctx->tls_recv_idx++;
        }
        recv_bytes = strlen(tosend);
    }

    return recv_bytes;
}

int32_t test_tls_send( NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend ) {
    char sendlog[10000];
    memcpy(sendlog, pBuffer, bytesToSend);
    sendlog[bytesToSend] = '\0';
    printf("----send----\n");
    printf("%s\n", sendlog);
    return bytesToSend;
}

static bool_t test_tls_initialize(const char *host, const char *tls_host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *tint, ESTError_t *err) {
    tint->recv = mock_config.test_tls_ctx.recv;
    tint->send = mock_config.test_tls_ctx.send;
    tint->pNetworkContext = mock_config.test_tls_ctx.pNetworkContext;
    return mock_config.test_tls_initialize_return_code;
}

static void test_tls_free(TransportInterface_t *ctx) {}

static void * before_each(const MunitParameter params[], void* user_data) {
    const RFC7030_Subsystem_Config_t *estCfg = rfc7030_get_config();

    opts.tlsInterface = (ESTTLSInterface_t *)estCfg->tls;
    opts.tlsInterface->initialize = test_tls_initialize;
    opts.tlsInterface->free = test_tls_free;
    opts.x509Interface = (ESTX509Interface_t *)estCfg->x509;

    mock_config.test_tls_initialize_return_code = EST_TRUE;
    mock_config.test_tls_ctx.recv = test_tls_recv;
    mock_config.test_tls_ctx.send = test_tls_send;
    mock_config.test_tls_ctx.pNetworkContext = NULL;

    memset(&err, 0, sizeof(err));
    return NULL;
}

static MunitResult test_init(const MunitParameter params[], void* data) {
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    munit_assert_not_null(ctx);

    est_free(&ctx);
    munit_assert_null(ctx);

    return MUNIT_OK;
}

static MunitResult test_connect_ko(const MunitParameter params[], void* data) {
    ESTError_t err;

    mock_config.test_tls_initialize_return_code = EST_FALSE;
    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    munit_assert_false(est_connect(ctx, "host", 443, &auth, &err));

    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_connect_ok(const MunitParameter params[], void* data) {
    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    munit_assert_true(est_connect(ctx, "host", 443, &auth, &err));

    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_cacerts_ok(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)cacerts_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    munit_assert_true(est_cacerts(ctx, &output, &err));
    munit_assert_true(output.chain_len == 1);

    char res[1024];
    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/cacerts_single.pem");
    munit_assert_true(crt_equals(output.chain[0], pf2crt(res)));

    est_cacerts_free(ctx, &output);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_cacerts_ok_with_label(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)cacerts_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    strcpy(opts.label, "custom-label");

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    munit_assert_true(est_cacerts(ctx, &output, &err));
    munit_assert_true(output.chain_len == 1);

    char res[1024];
    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/cacerts_single.pem");
    munit_assert_true(crt_equals(output.chain[0], pf2crt(res)));

    est_cacerts_free(ctx, &output);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_cacerts_failed_verify(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)cacerts_failed_verify_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    munit_assert_false(est_cacerts(ctx, &output, &err));

    est_cacerts_free(ctx, &output);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_cacerts_verify_ok(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)cacerts_verify_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    munit_assert_true(est_cacerts(ctx, &output, &err));
    munit_assert_true(output.chain_len == 3);

    char res[1024];
    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/cacerts_multiple1.pem");
    munit_assert_true(crt_equals(output.chain[0], pf2crt(res)));

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/cacerts_multiple2.pem");
    munit_assert_true(crt_equals(output.chain[1], pf2crt(res)));

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/cacerts_multiple3.pem");
    munit_assert_true(crt_equals(output.chain[2], pf2crt(res)));

    est_cacerts_free(ctx, &output);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_cacerts_incomplete_p7(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)cacerts_badp7_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    munit_assert_false(est_cacerts(ctx, &output, &err));

    est_cacerts_free(ctx, &output);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_enroll_ok(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)enroll_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    byte_t *req = "p10req";
    ESTCertificate_t *enrolled = est_enroll(ctx, req, strlen(req), EST_FALSE, &err);
    munit_assert_not_null(enrolled);

    char res[1024];
    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/enroll.pem");
    munit_assert_true(crt_equals(enrolled, pf2crt(res)));

    est_enroll_free(ctx, enrolled);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_enroll_retry_after_header(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)enroll_retry_after_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&opts, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    byte_t *req = "p10req";
    ESTCertificate_t *enrolled = est_enroll(ctx, req, strlen(req), EST_FALSE, &err);
    munit_assert_null(enrolled);
    munit_assert_true(err.code == EST_ERROR_ENROLL_RETRY);

    est_enroll_free(ctx, enrolled);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_enroll_missing_header(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)enroll_missing_header_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTClient_Options_t optsMod = opts;
    optsMod.strict8951 = EST_FALSE;

    ESTError_t err;    
    ESTClient_Ctx_t *ctx = est_initialize(&optsMod, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    byte_t *req = "p10req";
    ESTCertificate_t *enrolled = est_enroll(ctx, req, strlen(req), EST_FALSE, &err);
    munit_assert_null(enrolled);
    munit_assert_true(err.code == EST_HTTP_ERROR_BAD_HEADERS);

    est_enroll_free(ctx, enrolled);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitResult test_enroll_invalid_smime(const MunitParameter params[], void* data) {
    TestNetworkContext_t net_ctx;
    net_ctx.tls_recv_idx = 0;
    net_ctx.tls_recv = (const char **)enroll_invalid_smime_tls_recv;
    mock_config.test_tls_ctx.pNetworkContext = (NetworkContext_t *)&net_ctx;

    ESTClient_Options_t optsMod = opts;
    optsMod.strict8951 = EST_TRUE;

    ESTError_t err;
    ESTClient_Ctx_t *ctx = est_initialize(&optsMod, &err);
    est_connect(ctx, "host", 443, &auth, &err);

    ESTCaCerts_Info_t output;
    memset(&output, 0, sizeof(output));

    byte_t *req = "p10req";
    ESTCertificate_t *enrolled = est_enroll(ctx, req, strlen(req), EST_FALSE, &err);
    munit_assert_null(enrolled);
    munit_assert_true(err.code == EST_HTTP_ERROR_BAD_HEADERS);

    est_enroll_free(ctx, enrolled);
    est_free(&ctx);
    return MUNIT_OK;
}

static MunitTest test_suite_tests[] = {
  { (char*) "/est/lib/test_connect_ko", test_init, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_connect_ko", test_connect_ko, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_connect_ok", test_connect_ok, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_cacerts_ok", test_cacerts_ok, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_cacerts_ok_with_label", test_cacerts_ok_with_label, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_cacerts_failed_verify", test_cacerts_failed_verify, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_cacerts_verify_ok", test_cacerts_verify_ok, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_cacerts_incomplete_p7", test_cacerts_incomplete_p7, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL }, 
  { (char*) "/est/lib/test_enroll_ok", test_enroll_ok, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_enroll_retry_after_header", test_enroll_retry_after_header, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_enroll_missing_header", test_enroll_missing_header, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/lib/test_enroll_invalid_smime", test_enroll_invalid_smime, before_each, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

/* Now we'll actually declare the test suite.  You could do this in
 * the main function, or on the heap, or whatever you want. */
static const MunitSuite test_suite = {
  /* This string will be prepended to all test names in this suite;
   * for example, "/example/rand" will become "/µnit/example/rand".
   * Note that, while it doesn't really matter for the top-level
   * suite, NULL signal the end of an array of tests; you should use
   * an empty string ("") instead. */
  (char*) "est",
  /* The first parameter is the array of test suites. */
  test_suite_tests,
  /* In addition to containing test cases, suites can contain other
   * test suites.  This isn't necessary in this example, but it can be
   * a great help to projects with lots of tests by making it easier
   * to spread the tests across many files.  This is where you would
   * put "other_suites" (which is commented out above). */
  NULL,
  /* An interesting feature of µnit is that it supports automatically
   * running multiple iterations of the tests.  This is usually only
   * interesting if you make use of the PRNG to randomize your tests
   * cases a bit, or if you are doing performance testing and want to
   * average multiple runs.  0 is an alias for 1. */
  1,
  /* Just like MUNIT_TEST_OPTION_NONE, you can provide
   * MUNIT_SUITE_OPTION_NONE or 0 to use the default settings. */
  MUNIT_SUITE_OPTION_NONE
};


int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
  /* we'll actually run our test suite!  That second argument
   * is the user_data parameter which will be passed either to the
   * test or (if provided) the fixture setup function. */
  return munit_suite_main(&test_suite, (void*) "µnit", argc, argv);
}