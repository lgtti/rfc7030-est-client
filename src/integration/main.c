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
bool_t pop_create_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err);

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


static MunitResult test_client_cacerts(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts.pem");
    char cacerts[20000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_implicit.pem");

    char implicit_ta[20000];
    size_t implicit_ta_len = 20000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));

    RFC7030_Options_t opts;
    opts.host = "localhost";
    opts.port = 8443;
    opts.label = NULL;
    opts.cachain = cacerts;

    munit_assert_true(rfc7030_request_cachain(&opts, implicit_ta, implicit_ta_len, &err));
    munit_assert_true(crt_equals(pem2crt(implicit_ta), pf2crt(res)));

    return MUNIT_OK;
}

static MunitResult test_client_cacerts_invalid_est_ta(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts_invalid.pem");
    char cacerts[20000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_implicit.pem");

    char implicit_ta[20000];
    size_t implicit_ta_len = 20000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));

    RFC7030_Options_t opts;
    opts.host = "localhost";
    opts.port = 8443;
    opts.label = NULL;
    opts.cachain = cacerts;

    munit_assert_false(rfc7030_request_cachain(&opts, implicit_ta, implicit_ta_len, &err));

    return MUNIT_OK;
}

static MunitResult test_client_enroll_invalid_est_ta(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts_invalid.pem");
    char cacerts[20000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_implicit.pem");

    char implicit_ta[20000];
    size_t implicit_ta_len = 20000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));

    RFC7030_Enroll_Options_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.opts.host = "localhost";
    cfg.opts.port = 8443;
    cfg.opts.label = NULL;
    cfg.opts.cachain = cacerts;

    munit_assert_false(rfc7030_request_certificate(&cfg, 
        implicit_ta, 
        implicit_ta_len,
        NULL,
        0,
        &err));

    return MUNIT_OK;
}

static MunitResult test_client_enroll_crt(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts.pem");
    char cacerts[5000];
    size_t cacerts_len = read_file(res, "rt", cacerts);
    
    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/csr.pem");
    char csr[5000];
    size_t csr_len = read_file(res, "rt", csr);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/preenrollment.p12");
    char p12[5000];
    size_t p12_len = read_file(res, "rb", p12);

    char implicit_ta[5000];
    size_t implicit_ta_len = 5000;

    char enrolled[5000];
    size_t enrolled_len = 5000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));
    
    RFC7030_Enroll_Options_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.opts.host = "localhost";
    cfg.opts.port = 9443;
    cfg.opts.label = NULL;
    cfg.opts.cachain = cacerts;
    cfg.csr_ctx = (CsrCtx_t *)csr;

    const RFC7030_Subsystem_Config_t *implCfg = rfc7030_get_config();
    implCfg->parse_p12(p12, p12_len, "12345", &cfg.auth, &err);

    munit_assert_true(rfc7030_request_certificate(&cfg, 
        implicit_ta, 
        implicit_ta_len,
        enrolled,
        enrolled_len,
        &err));

    munit_assert_true(is_issuer(pem2crt(implicit_ta), pem2crt(enrolled)));

    return MUNIT_OK;
}

static MunitResult test_client_enroll_basic(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts.pem");
    char cacerts[5000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/csr.pem");
    char csr[5000];
    size_t csr_len = read_file(res, "rt", csr);
    
    char implicit_ta[5000];
    size_t implicit_ta_len = 5000;

    char enrolled[5000];
    size_t enrolled_len = 5000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));
    
    RFC7030_Enroll_Options_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.opts.host = "localhost";
    cfg.opts.port = 8443;
    cfg.opts.label = NULL;
    cfg.opts.cachain = cacerts;
    cfg.csr_ctx = (CsrCtx_t *)csr;

    const RFC7030_Subsystem_Config_t *implCfg = rfc7030_get_config();
    implCfg->parse_basicauth("estuser:estpwd", &cfg.auth, &err);
    
    munit_assert_true(rfc7030_request_certificate(&cfg, 
        implicit_ta, 
        implicit_ta_len,
        enrolled,
        enrolled_len,
        &err));

    munit_assert_true(is_issuer(pem2crt(implicit_ta), pem2crt(enrolled)));

    return MUNIT_OK;
}

static MunitResult test_client_renew(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts.pem");
    char cacerts[5000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/csr.pem");
    char csr[5000];
    size_t csr_len = read_file(res, "rt", csr);

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/client-renewal.p12");
    char p12[5000];
    size_t p12_len = read_file(res, "rb", p12);
    
    char implicit_ta[5000];
    size_t implicit_ta_len = 5000;

    char enrolled[5000];
    size_t enrolled_len = 5000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));
    ESTAuthData_t auth;
    memset(&auth, 0, sizeof(auth));
    
    RFC7030_Enroll_Options_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.opts.host = "localhost";
    cfg.opts.port = 9443;  // Use mTLS port for renewal
    cfg.opts.label = NULL;
    cfg.opts.cachain = cacerts;
    cfg.csr_ctx = (CsrCtx_t *)csr;

    // For renewal, we need mTLS authentication with existing certificate
    const RFC7030_Subsystem_Config_t *implCfg = rfc7030_get_config();
    implCfg->parse_p12(p12, p12_len, "testpass", &cfg.auth, &err);

    munit_assert_true(rfc7030_renew_certificate(&cfg, 
        implicit_ta, 
        implicit_ta_len,
        enrolled,
        enrolled_len,
        &err));

    munit_assert_true(is_issuer(pem2crt(implicit_ta), pem2crt(enrolled)));

    return MUNIT_OK;
}

static MunitResult test_client_enroll_basic_pop(const MunitParameter params[], void* data) {
    rfc7030_init();

    char res[1024];

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/rfc_cacerts.pem");
    char cacerts[5000];
    size_t cacerts_len = read_file(res, "rt", cacerts);

    char csr_ctx[5000];
    strcpy(csr_ctx, TEST_RESOURCE_FOLDER);
    strcat(csr_ctx, "/eckey.pem");

    strcpy(res, TEST_RESOURCE_FOLDER);
    strcat(res, "/preenrollment.p12");
    char p12[5000];
    size_t p12_len = read_file(res, "rb", p12);
    
    char implicit_ta[5000];
    size_t implicit_ta_len = 5000;

    char enrolled[5000];
    size_t enrolled_len = 5000;

    ESTError_t err;
    memset(&err, 0, sizeof(err));
    
    RFC7030_Enroll_Options_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.opts.host = "localhost";
    cfg.opts.port = 8443;
    cfg.opts.label = NULL;
    cfg.opts.cachain = cacerts;
    cfg.csr_ctx = (CsrCtx_t *)csr_ctx;

    RFC7030_Subsystem_Config_t *implCfg = rfc7030_get_config();
    implCfg->parse_p12(p12, p12_len, "12345", &cfg.auth, &err);
    implCfg->get_csr = pop_create_csr;

    munit_assert_true(rfc7030_request_certificate(&cfg, 
        implicit_ta, 
        implicit_ta_len,
        enrolled,
        enrolled_len,
        &err));

    munit_assert_true(is_issuer(pem2crt(implicit_ta), pem2crt(enrolled)));

    return MUNIT_OK;
}

static MunitTest test_suite_tests[] = {
  { (char*) "/est/int/test_client_cacerts", test_client_cacerts, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/int/test_client_cacerts_invalid_est_ta", test_client_cacerts_invalid_est_ta, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/int/test_client_enroll_invalid_est_ta", test_client_enroll_invalid_est_ta, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
 // { (char*) "/est/int/test_client_enroll_crt", test_client_enroll_crt, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/int/test_client_enroll_basic", test_client_enroll_basic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { (char*) "/est/int/test_client_renew", test_client_renew, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
 // { (char*) "/est/int/test_client_enroll_basic_pop", test_client_enroll_basic_pop, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
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