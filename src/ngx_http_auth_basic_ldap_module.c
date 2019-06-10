#define LDAP_DEPRECATED 1


#include <ldap.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>


typedef struct {
    ngx_str_t realm;
    ngx_str_t ldap_url;
    ngx_str_t ldap_bind_dn;
} ngx_http_auth_basic_ldap_loc_conf_t;


static ngx_int_t ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void *ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_basic_ldap_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_auth_basic_ldap_commands[] = {

    { ngx_string("auth_basic_ldap_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_ldap_loc_conf_t, realm),
      NULL },

    { ngx_string("auth_basic_ldap_url"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_url),
      NULL },

    { ngx_string("auth_basic_ldap_bind_dn"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_bind_dn),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_basic_ldap_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_basic_ldap_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_basic_ldap_create_loc_conf,   /* create location configuration */
    ngx_http_auth_basic_ldap_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_basic_ldap_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_basic_ldap_module_ctx,       /* module context */
    ngx_http_auth_basic_ldap_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_auth_basic_ldap_loc_conf_t *alcf;
    u_char *user;

    int ldap_response;
    int desired_version = LDAP_VERSION3;
    int auth_method = LDAP_AUTH_SIMPLE;
    size_t len;

    LDAP *ld;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);

    if (alcf->ldap_url.len == 0
        || alcf->ldap_bind_dn.len == 0
    ) {
        return NGX_DECLINED;
    }

    if (alcf->realm.len == 3 && ngx_strncmp(alcf->realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!r->headers_in.passwd.len) {
        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }

    ldap_response = ldap_initialize(&ld, (char *) alcf->ldap_url.data);
    if (ldap_response) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ldap_initialize on \"%V\" failed: %s",
                      &alcf->ldap_url, ldap_err2string(ldap_response));

        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }

    ldap_response = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (ldap_response != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ldap_set_option failed: %s",
                      ldap_err2string(ldap_response));

        return NGX_ERROR;
    }

    len = r->headers_in.user.len + sizeof("%s@%s") - 1 - 1 - 1 + alcf->ldap_bind_dn.len;
    user = ngx_pcalloc(r->pool, len);
    ngx_snprintf(user, len - 1, "%V@%V", &r->headers_in.user, &alcf->ldap_bind_dn);

    ldap_response = ldap_bind_s(ld, (char *) user, (char *) r->headers_in.passwd.data, auth_method);
    if (ldap_response != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ldap_bind_s failed: %s",
                      ldap_err2string(ldap_response));

        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }

    ldap_unbind_s(ld);

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}


static void *
ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_basic_ldap_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_ldap_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_basic_ldap_loc_conf_t  *prev = parent;
    ngx_http_auth_basic_ldap_loc_conf_t  *conf = child;

    ngx_conf_merge_str_value(conf->realm, prev->realm, "off");
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_url, NULL);
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_bind_dn, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_basic_ldap_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_basic_ldap_handler;

    return NGX_OK;
}
