#include <stdlib.h>
#include <string.h>

#include "rfc7030.h"
#include "cargs.h"
#include "custom_config.h"

static struct cag_option options[] = {
    {
        .identifier = 's',
        .access_letters = "s",
        .access_name = "server",
        .value_name = "HOSTNAME",
        .description = "EST server hostname - no https prefix required, no port, no extra path"
    },
    {
        .identifier = 'p',
        .access_letters = "p",
        .access_name = "port",
        .value_name = "443",
        .description = "EST server ednpoint port number (default 443)"
    },
    {
        .identifier = 'h',
        .access_letters = "h",
        .access_name = "help",
        .value_name = NULL,
        .description = "Print help"
    },
    {
        .identifier = 'i',
        .access_letters = "i",
        .access_name = "insecure",
        .value_name = NULL,
        .description = "Skip verify of EST Server certificate chain validity - don't use it in production!"
    },
    {
        .identifier = 'u',
        .access_letters = "u",
        .access_name = "use_original_spec",
        .value_name = NULL,
        .description = "Set this flag if you want to disable support for RFC 8951"
    },
    {
        .identifier = 'l',
        .access_letters = "l",
        .access_name = "label",
        .value_name = "LABEL",
        .description = "Additional path segment in EST endpoints (e.g. /.well-known/est/[label]/simpleenroll)"
    },
    {
        .identifier = 'v',
        .access_letters = NULL,
        .access_name = "server-chain",
        .value_name = "FILENAME",
        .description = "EST Server certificate chain in PEM format to validate endpoint - ignored if --insecure flag is set."
    },
    {
        .identifier = 'c',
        .access_letters = NULL,
        .access_name = "csr",
        .value_name = "FILENAME",
        .description = "Client CSR - Certificate Signing Request - filename in PEM format."
    },
    {
        .identifier = 'x',
        .access_name = "p12",
        .value_name = "FILENAME",
        .description = "Authentication for EST Server connection using mTLS and P12 credential file"
    },
    {
        .identifier = 'r',
        .access_name = "p12-password",
        .value_name = "P12 FILENAME PASSWORD",
        .description = "Password for p12 file specified using --p12 flag"
    },
    {
        .identifier = 'b',
        .access_name = "basic-auth",
        .value_name = "USERNAME:PASSWORD",
        .description = "Authentication for EST Server connection using http basic auth. Value should be username:password (but password can be empty)"
    },
    {
        .identifier = 'f',
        .access_name = "output-ca",
        .value_name = "PEM FILENAME PATH",
        .description = "Filename and path used to save the CA certificates"
    },
    {
        .identifier = 'z',
        .access_name = "output-crt",
        .value_name = "PEM FILENAME PATH",
        .description = "Filename and path used to save the Enrolled/Renewed certificate"
    },
    {
        .identifier = 'k',
        .access_name = "input-key",
        .value_name = "KEY FILENAME PATH",
        .description = "Private key used to request enrollment"
    },
    {
        .identifier = 'e',
        .access_name = "input-cert",
        .value_name = "CERT FILENAME PATH",
        .description = "Certificate signed by private key from k flag used to request enrollment"
    }
};

static size_t read_file(const char *name, const char *flags, char *output) {
    FILE *fp = fopen(name, flags);
    if(!fp) {        
        LOG_ERROR(("Failed to open %s from resource file\n", name))
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0L, SEEK_END);
    long fp_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    
    size_t res_len = fp_size;
    
    fread(output, res_len, 1, fp);
    output[res_len] = '\0';
    fclose(fp);

    LOG_DEBUG(("%s(%d): \n", name, (int)res_len))
    LOG_DEBUG(("%s\n", output))

    return res_len;
}

static bool_t write_file(const char *name, const char *flags, char *input) {
    FILE *fp = fopen(name, flags);
    if(!fp) {        
        LOG_ERROR(("Failed to open %s from resource file\n", name))
        exit(EXIT_FAILURE);
    }

    return fputs(input, fp) != EOF;
}

int main(int argc, char *argv[]) {
    bool_t enroll = EST_FALSE;
    bool_t renew = EST_FALSE;
    bool_t cacerts = EST_FALSE;

    const char *host = NULL;
    int port = EST_TCP_PORT;
    bool_t skip_tls_verify = EST_FALSE;
    bool_t disable_strict_8951 = EST_FALSE;
    const char *label = NULL;
    
    char chain_content[20000];
    size_t chain_content_len = 0;

    char csr_content[5000];
    size_t csr_content_len = 0;

    char p12_content[10000];
    size_t p12_content_len = 0;

    const char *chain_filename = NULL;
    const char *csr_filename = NULL;
    const char *p12_filename = NULL;
    const char *p12_password = NULL;
    const char *basic_auth = NULL;
    const char *output_ca = NULL;
    const char *output_crt = NULL;

    cag_option_context context;
    char identifier;
    const char *raw_value;
    char *ptr;
    bool_t failed = EST_FALSE;
    bool_t noarg = EST_TRUE;

    cag_option_prepare(&context, options, CAG_ARRAY_SIZE(options), argc, argv);

    rfc7030_init();

    while (cag_option_fetch(&context)) {
        noarg = EST_FALSE;

        identifier = cag_option_get(&context);
        switch (identifier) {
        case 's': 
            host = cag_option_get_value(&context);
            break;
        case 'p':
            raw_value = cag_option_get_value(&context);
            port = (int)strtol(raw_value, &ptr, 10);
            break;
        case 'i':
            skip_tls_verify = EST_TRUE;
            break;
        case 'l': 
            label = cag_option_get_value(&context);
            break;
        case 'v': 
            chain_filename = cag_option_get_value(&context);
            break;
        case 'c': 
            csr_filename = cag_option_get_value(&context);
            break;
        case 'x':
            p12_filename = cag_option_get_value(&context);
            break;
        case 'r':
            p12_password = cag_option_get_value(&context);
            break;
        case 'b':
            basic_auth = cag_option_get_value(&context);
            break;
        case 'f':
            output_ca = cag_option_get_value(&context);
            break;
        case 'z':
            output_crt = cag_option_get_value(&context);
            break;
        case 'u':
            disable_strict_8951 = EST_TRUE;
            break;
        case 'h':
            printf("Usage: rfc7030-est-client [OPTIONs] [enroll|renew|cacerts]\n");
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return EXIT_FAILURE;
        }
    }

    if(noarg) {
        printf("Usage: rfc7030-est-client [OPTIONs] [enroll|renew|cacerts]\n");
        cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
        return EXIT_FAILURE;
    }

    int operation_param_num = argc - context.index;
    if (operation_param_num != 1) {
        LOG_ERROR(("Missing operation enroll, renew, cacerts\n"));
        printf("Usage: rfc7030-est-client [OPTIONs] [enroll|renew|cacerts]\n");
        cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
        return EXIT_FAILURE;
    }

    const char *operation = argv[context.index]; // last parameter
    if(strcmp(operation, "enroll") == 0) {
        enroll = EST_TRUE;
    }
    if(strcmp(operation, "renew") == 0) {
        renew = EST_TRUE;
    }
    if(strcmp(operation, "cacerts") == 0) {
        cacerts = EST_TRUE;
    }

    ESTError_t err;
    memset(&err, 0, sizeof(err));
    ESTAuthData_t auth;
    memset(&auth, 0, sizeof(auth));

    if(host == NULL) {
        LOG_ERROR(("Missing host parameter\n"));
        failed = EST_TRUE;
    }

    if(chain_filename) {
        chain_content_len = read_file(chain_filename, "rt", chain_content);
    } else if(!skip_tls_verify) {
        LOG_ERROR(("Please choose one of insecure flag or server chain flag.\n"));
        failed = EST_TRUE;
    }

    const RFC7030_Subsystem_Config_t *estCfg = rfc7030_get_config();
    
    RFC7030_Enroll_Options_t rfcConfig;
    memset(&rfcConfig, 0, sizeof(rfcConfig));
    rfcConfig.opts.host = host;
    rfcConfig.opts.port = port;
    rfcConfig.opts.disable_rfc8951 = disable_strict_8951;

    if(!skip_tls_verify) {
        rfcConfig.opts.cachain = chain_content;
    }

    rfcConfig.opts.label = label;

    char cacerts_pem[CLIENT_CACERT_MAX_LEN];

    if(enroll || renew) { 
        if(!csr_filename) {
            LOG_ERROR(("Missing csr parameter\n"));
            failed = EST_TRUE;
        } else {
            csr_content_len = read_file(csr_filename, "rt", csr_content);
            rfcConfig.csr_ctx = (CsrCtx_t *)csr_content;
        }

        if(!p12_filename && !basic_auth) {
            LOG_ERROR(("At least p12 or basic auth flag required\n"));
            failed = EST_TRUE;
        } else {
            if(p12_filename) {
                LOG_INFO(("Use mTLS X.509 Certificate authentication\n"));

                p12_content_len = read_file(p12_filename, "rb", p12_content);
                if(!estCfg->parse_p12(p12_content, p12_content_len, p12_password, &rfcConfig.auth, &err)) {
                    LOG_ERROR(("Invalid p12 (code=%d,native=%d,subsystem=%d): %s\n", err.code, err.native, err.subsystem, err.human));
                    failed = EST_TRUE;
                }
            } else if(basic_auth) {
                LOG_INFO(("Use HTTP Basic Auth authentication\n"));

                if(!estCfg->parse_basicauth(basic_auth, &rfcConfig.auth, &err)) {
                    LOG_ERROR(("Invalid basicauth (code=%d,native=%d,subsystem=%d): %s\n", err.code, err.native, err.subsystem, err.human));
                    failed = EST_TRUE;
                }
            }
        }

        if(failed) {
            printf("Usage: rfc7030-est-client [OPTIONs] [enroll|renew|cacerts]\n");
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return EXIT_FAILURE;
        }

        char enrolled[CLIENT_ENROLLED_MAX_LEN];

        if(renew) {
            if(!rfc7030_renew_certificate(&rfcConfig, cacerts_pem, CLIENT_CACERT_MAX_LEN, enrolled, CLIENT_ENROLLED_MAX_LEN, &err)) {
                LOG_ERROR(("Renew failed (code=%d,native=%d,subsystem=%d): %s\n", err.code, err.native, err.subsystem, err.human));
                return EXIT_FAILURE;
            }
        } else {
            if(!rfc7030_request_certificate(&rfcConfig, cacerts_pem, CLIENT_CACERT_MAX_LEN, enrolled, CLIENT_ENROLLED_MAX_LEN, &err)) {
                LOG_ERROR(("Enrollment failed (code=%d,native=%d,subsystem=%d): %s\n", err.code, err.native, err.subsystem, err.human));
                return EXIT_FAILURE;
            }
        }
        
        LOG_INFO(("CACerts:\n"));
        LOG_INFO(("%s\n", cacerts_pem));
        LOG_INFO(("Enrolled certificate:\n"));
        LOG_INFO(("%s\n", enrolled));

        if(output_ca) {
            if(!write_file(output_ca, "wt", cacerts_pem)) {
                LOG_ERROR(("Failed to write output\n"));
                return EXIT_FAILURE;
            }
        }

        if(output_crt) {
            if(!write_file(output_crt, "a+", enrolled)) {
                LOG_ERROR(("Failed to write output\n"));
                return EXIT_FAILURE;
            }
        }
    }

    if(cacerts) {
        if(!rfc7030_request_cachain(&rfcConfig.opts, cacerts_pem, CLIENT_CACERT_MAX_LEN, &err)) {
            LOG_ERROR(("CAcerts failed (code=%d,native=%d,subsystem=%d): %s\n", err.code, err.native, err.subsystem, err.human));
            return EXIT_FAILURE;
        }
        
        LOG_INFO(("CACerts:\n"));
        LOG_INFO(("%s\n", cacerts_pem));

        if(output_ca) {
            if(!write_file(output_ca, "wt", cacerts_pem)) {
                LOG_ERROR(("Failed to write output\n"));
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}