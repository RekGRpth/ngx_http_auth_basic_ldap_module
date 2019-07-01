#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t realm;
    ngx_str_t ldap_url;
    ngx_str_t ldap_bind_dn;
    ngx_str_t ldap_search_base;
    ngx_http_complex_value_t *ldap_search_filter;
    ngx_array_t *ldap_search_attr;
} ngx_http_auth_basic_ldap_loc_conf_t;

ngx_module_t ngx_http_auth_basic_ldap_module;

static ngx_command_t ngx_http_auth_basic_ldap_commands[] = {
  { .name = ngx_string("auth_basic_ldap_realm"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, realm),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_url"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_url),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_bind_dn"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_bind_dn),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_search_base"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_search_base),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_search_filter"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_search_filter),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_search_attr"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_array_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, ldap_search_attr),
    .post = NULL },
    ngx_null_command
};

static char *ngx_str_t_to_char(ngx_pool_t *pool, ngx_str_t s) {
    char *c = ngx_pcalloc(pool, (s.len + 1) * sizeof(char));
    if (!c) return NULL;
    ngx_memcpy(c, s.data, s.len);
    return c;
}

static ngx_str_t char_to_ngx_str_t(ngx_pool_t *pool, char *c) {
    size_t len = ngx_strlen(c);
    ngx_str_t s = {len, ngx_pnalloc(pool, len * sizeof(char))};
    if (s.data) ngx_memcpy(s.data, c, len); else s.len = 0;
    return s;
}

static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (!r->headers_out.www_authenticate) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    size_t len = sizeof("Basic realm=\"\"") - 1 + realm->len;
    u_char *basic = ngx_pnalloc(r->pool, len * sizeof(u_char));
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
    if (alcf->realm.len == 3 && ngx_strncmp(alcf->realm.data, "off", 3) == 0) return NGX_DECLINED;
    switch (ngx_http_auth_basic_user(r)) {
        case NGX_DECLINED: ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "no user/password was provided for basic authentication"); goto ret;
        case NGX_ERROR: return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!r->headers_in.passwd.len) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "no password was provided for basic authentication"); goto ret; }
    LDAP *ld;
    int rc = ldap_initialize(&ld, (char *)alcf->ldap_url.data);
    if (rc) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_initialize on \"%V\" failed: %s", &alcf->ldap_url, ldap_err2string(rc)); goto ret; }
    int desired_version = LDAP_VERSION3;
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (rc != LDAP_OPT_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_set_option failed: %s", ldap_err2string(rc)); goto unbind; }
    size_t len = r->headers_in.user.len + sizeof("%V@%V") - 1 - 1 - 1 + alcf->ldap_bind_dn.len;
    u_char *user = ngx_pcalloc(r->pool, len * sizeof(u_char));
    ngx_snprintf(user, len - 1, "%V@%V", &r->headers_in.user, &alcf->ldap_bind_dn);
    rc = ldap_bind_s(ld, (char *)user, (char *)r->headers_in.passwd.data, LDAP_AUTH_SIMPLE);
    if (rc != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_bind_s failed: %s", ldap_err2string(rc)); goto unbind; }
    LDAPMessage *msg;
    if (alcf->ldap_search_base.len) {
        char *filter = NULL;
        if (alcf->ldap_search_filter != NULL) {
            ngx_str_t value;
            if (ngx_http_complex_value(r, alcf->ldap_search_filter, &value) != NGX_OK) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto unbind; }
            filter = ngx_str_t_to_char(r->pool, value);
        }
        char **attrs = NULL;
        if (alcf->ldap_search_attr && alcf->ldap_search_attr->nelts) {
            attrs = ngx_pcalloc(r->pool, sizeof(char *) * (alcf->ldap_search_attr->nelts + 1));
            if (!attrs) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!attrs"); goto unbind; }
            ngx_str_t *elt = alcf->ldap_search_attr->elts;
            for (ngx_uint_t i = 0; i < alcf->ldap_search_attr->nelts; i++) attrs[i] = (char *)elt[i].data;
        }
        rc = ldap_search_s(ld, (char *)alcf->ldap_search_base.data, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &msg);
        if (rc != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_search_s failed: %s: %s", ldap_err2string(rc), filter); goto msgfree; }
        rc = ldap_count_entries(ld, msg);
        if (rc <= 0) { ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ldap_count_entries == %i", rc); goto msgfree; }
        for (LDAPMessage *entry = ldap_first_entry(ld, msg); entry; entry = ldap_next_entry(ld, entry)) {
            BerElement *ber;
            for (char *attr = ldap_first_attribute(ld, entry, &ber); attr; attr = ldap_next_attribute(ld, entry, ber)) {
                char **vals = ldap_get_values(ld, entry, attr);
                if (!vals) continue;
                int cnt = ldap_count_values(vals);
                for (int i = 0; i < cnt; i++) {
                    ngx_str_t key;
                    if (cnt > 1) {
                        key.len = ngx_strlen(attr) + sizeof("LDAP-%s_%i") - 1 - 1 - 1 - 1;
                        for (int number = i; number /= 10; key.len++);
                        key.data = ngx_pcalloc(r->pool, key.len * sizeof(u_char));
                        if (key.data) ngx_snprintf(key.data, key.len, "LDAP-%s_%i", attr, i);
                    } else {
                        key.len = ngx_strlen(attr) + sizeof("LDAP-%s") - 1 - 1 - 1;
                        key.data = ngx_pcalloc(r->pool, key.len * sizeof(u_char));
                        if (key.data) ngx_snprintf(key.data, key.len, "LDAP-%s", attr);
                    }
                    ngx_str_t value = char_to_ngx_str_t(r->pool, vals[i]);
                    ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers);
                    if (h && key.data && value.data) {
                        h->key = key;
                        h->value = value;
                    }
                }
                ldap_value_free(vals);
            }
            ber_free(ber, 0);
        }
        ldap_msgfree(msg);
    }
    ldap_unbind_s(ld);
    return NGX_OK;
msgfree:
    ldap_msgfree(msg);
unbind:
    ldap_unbind_s(ld);
ret:
    return ngx_http_auth_basic_ldap_set_realm(r, &alcf->realm);
}

static ngx_int_t ngx_http_auth_basic_ldap_postconfiguration(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (!h) return NGX_ERROR;
    *h = ngx_http_auth_basic_ldap_handler;
    return NGX_OK;
}

static void *ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_ldap_loc_conf_t));
    if (!conf) return NULL;
    conf->ldap_search_attr = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_basic_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_basic_ldap_loc_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->realm, prev->realm, "off");
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_url, "");
    ngx_conf_merge_str_value(conf->ldap_url, prev->ldap_bind_dn, "");
    ngx_conf_merge_str_value(conf->ldap_search_base, prev->ldap_search_base, "");
    if (conf->ldap_search_filter == NULL) conf->ldap_search_filter = prev->ldap_search_filter;
    ngx_conf_merge_ptr_value(conf->ldap_search_attr, prev->ldap_search_attr, NULL);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_auth_basic_ldap_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_auth_basic_ldap_postconfiguration,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_auth_basic_ldap_create_loc_conf,
    .merge_loc_conf = ngx_http_auth_basic_ldap_merge_loc_conf
};

ngx_module_t ngx_http_auth_basic_ldap_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_auth_basic_ldap_module_ctx,
    .commands = ngx_http_auth_basic_ldap_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
