#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t realm;
    ngx_str_t ldap_url;
    ngx_str_t ldap_bind_dn;
    ngx_str_t ldap_bind_passwd;
    ngx_str_t ldap_search_base;
    ngx_str_t ldap_search_attr;
} ngx_http_auth_basic_ldap_loc_conf_t;

ngx_module_t ngx_http_auth_basic_ldap_module;

static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (!r->headers_out.www_authenticate) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    size_t len = sizeof("Basic realm=\"\"") - 1 + realm->len;
    u_char *basic = ngx_pnalloc(r->pool, len);
    if (!basic) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    u_char *p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';
    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;
    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r) {
    ngx_http_auth_basic_ldap_loc_conf_t *alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    if (alcf->ldap_url.len == 0 || alcf->ldap_bind_dn.len == 0 || alcf->ldap_bind_passwd.len == 0 || alcf->ldap_search_base.len == 0) return NGX_DECLINED;
    if (alcf->realm.len == 3 && ngx_strncmp(alcf->realm.data, "off", 3) == 0) return NGX_DECLINED;
    ngx_int_t rc = ngx_http_auth_basic_user(r);
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "no user/password was provided for basic authentication");
        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }
    if (rc == NGX_ERROR) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (!r->headers_in.passwd.len) return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    LDAP *ld;
    int ldap_response = ldap_initialize(&ld, (char *) alcf->ldap_url.data);
    if (ldap_response) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_initialize on \"%V\" failed: %s", &alcf->ldap_url, ldap_err2string(ldap_response));
        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }
    int desired_version = LDAP_VERSION3;
    ldap_response = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (ldap_response != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_set_option failed: %s", ldap_err2string(ldap_response));
        return NGX_ERROR;
    }
    size_t len = r->headers_in.user.len + sizeof("%s@%s") - 1 - 1 - 1 + alcf->ldap_bind_dn.len;
    u_char *user = ngx_pcalloc(r->pool, len);
    ngx_snprintf(user, len - 1, "%V@%V", &r->headers_in.user, &alcf->ldap_bind_dn);
    ldap_response = ldap_bind_s(ld, (char *) user, (char *) r->headers_in.passwd.data, LDAP_AUTH_SIMPLE);
    if (ldap_response != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_bind_s failed: %s", ldap_err2string(ldap_response));
        return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
    }
    ldap_unbind_s(ld);
    return NGX_OK;
}

static ngx_int_t ngx_http_auth_basic_ldap_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (!h) return NGX_ERROR;
    *h = ngx_http_auth_basic_ldap_handler;
    return NGX_OK;
}

static void *ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_ldap_loc_conf_t));
    if (!conf) return NULL;
    return conf;
}

static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_basic_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_basic_ldap_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->realm, prev->realm, "off");
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_url, NULL);
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_bind_dn, NULL);
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_bind_passwd, NULL);
    ngx_conf_merge_str_value(conf->ldap_search_base, prev->ldap_search_base, NULL);
    ngx_conf_merge_str_value(conf->ldap_search_attr, prev->ldap_search_attr, "uid");
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_auth_basic_ldap_commands[] = {
  { ngx_string("auth_basic_ldap_realm"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, realm),
    NULL },

  { ngx_string("auth_basic_ldap_url"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_url),
    NULL },

  { ngx_string("auth_basic_ldap_bind_dn"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_bind_dn),
    NULL },

  { ngx_string("auth_basic_ldap_bind_password"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_bind_passwd),
    NULL },

  { ngx_string("auth_basic_ldap_search_base"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_search_base),
    NULL },

  { ngx_string("auth_basic_ldap_search_attr"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_search_attr),
    NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_basic_ldap_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_auth_basic_ldap_init,            /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_auth_basic_ldap_create_loc_conf, /* create location configuration */
    ngx_http_auth_basic_ldap_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_basic_ldap_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_basic_ldap_module_ctx,  /* module context */
    ngx_http_auth_basic_ldap_commands,     /* module directives */
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
