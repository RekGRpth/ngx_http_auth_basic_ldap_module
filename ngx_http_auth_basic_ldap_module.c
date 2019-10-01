#include <openldap.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t attr;
#if (NGX_PCRE)
    ngx_http_complex_value_t complex_value;
    ngx_http_regex_t *http_regex;
#endif
} ngx_http_auth_basic_ldap_attr_t;

typedef struct {
    ngx_array_t *attrs;
    ngx_http_complex_value_t *filter;
    ngx_str_t base;
    ngx_str_t bind;
    ngx_str_t header;
    ngx_str_t realm;
    ngx_str_t uri;
} ngx_http_auth_basic_ldap_location_conf_t;

ngx_module_t ngx_http_auth_basic_ldap_module;

char *ngx_http_auth_basic_ldap_attr_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = conf;
    if (location_conf->attrs == NGX_CONF_UNSET_PTR && !(location_conf->attrs = ngx_array_create(cf->pool, 4, sizeof(ngx_http_auth_basic_ldap_attr_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_http_auth_basic_ldap_attr_t *attr = ngx_array_push(location_conf->attrs);
    if (!attr) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_memzero(attr, sizeof(ngx_http_auth_basic_ldap_attr_t));
    ngx_str_t *value = cf->args->elts;
    attr->attr = value[1];
#if (NGX_PCRE)
    if (cf->args->nelts <= 2) return NGX_CONF_OK;
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t err = {NGX_MAX_CONF_ERRSTR, errstr};
    ngx_regex_compile_t rc;
    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pattern = value[2];
    rc.options = NGX_REGEX_CASELESS;
    rc.err = err;
    if (!(attr->http_regex = ngx_http_regex_compile(cf, &rc))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &attr->complex_value;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "captcha: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
#endif
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_auth_basic_ldap_commands[] = {
  { .name = ngx_string("auth_basic_ldap_realm"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, realm),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_uri"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, uri),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_bind"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, bind),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_base"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, base),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_header"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, header),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_filter"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, filter),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_attr"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1
#if (NGX_PCRE)
    |NGX_CONF_TAKE3
#endif
    ,
    .set = ngx_http_auth_basic_ldap_attr_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, attrs),
    .post = NULL },
    ngx_null_command
};

static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    if (!(r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    size_t len = sizeof("Basic realm=\"\"") - 1 + realm->len;
    u_char *basic = ngx_pnalloc(r->pool, len);
    if (!basic) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';
    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;
    return NGX_HTTP_UNAUTHORIZED;
}

static int ngx_http_auth_basic_ldap_lc_add(LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr, struct ldap_conncb *ctx) {
    ngx_http_request_t *r = ctx->lc_arg;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    return LDAP_SUCCESS;
}

static void ngx_http_auth_basic_ldap_lc_del(LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx) {
    ngx_http_request_t *r = ctx->lc_arg;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
}

static ngx_int_t ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r) {
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    if (location_conf->realm.len == 3 && ngx_strncmp(location_conf->realm.data, "off", 3) == 0) return NGX_DECLINED;
    switch (ngx_http_auth_basic_user(r)) {
        case NGX_DECLINED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: no user/password was provided for basic authentication"); goto ret;
        case NGX_ERROR: return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!r->headers_in.passwd.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: no password was provided for basic authentication"); goto ret; }
    LDAP *ld;
    u_char *uri = ngx_pnalloc(r->pool, location_conf->uri.len + 1);
    if (!uri) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto ret; }
    (void) ngx_cpystrn(uri, location_conf->uri.data, location_conf->uri.len + 1);
    int rc;
    if ((rc = ldap_initialize(&ld, (const char *)uri)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_initialize on \"%V\" failed: %s", &location_conf->uri, ldap_err2string(rc)); goto ret; }
    int desired_version = LDAP_VERSION3;
    if ((rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version)) != LDAP_OPT_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_set_option failed: %s", ldap_err2string(rc)); goto unbind; }
    const struct ldap_conncb ctx = {ngx_http_auth_basic_ldap_lc_add, ngx_http_auth_basic_ldap_lc_del, r};
    if ((rc = ldap_set_option(ld, LDAP_OPT_CONNECT_CB, &ctx)) != LDAP_OPT_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_set_option failed: %s", ldap_err2string(rc)); goto unbind; }
    size_t len = r->headers_in.user.len + sizeof("@") - 1 + location_conf->bind.len;
    u_char *who = ngx_pnalloc(r->pool, len + 1);
    u_char *last = ngx_snprintf(who, len, "%V@%V", &r->headers_in.user, &location_conf->bind);
    if (last != who + len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto unbind; }
    *last = '\0';
    struct berval cred = {r->headers_in.passwd.len, (char *)r->headers_in.passwd.data};
    if ((rc = ldap_sasl_bind_s(ld, (const char *)who, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_sasl_bind_s failed: %s", ldap_err2string(rc)); goto unbind; }
    LDAPMessage *msg;
    if (location_conf->base.len) {
        u_char *filter = NULL;
        if (location_conf->filter) {
            ngx_str_t value;
            if (ngx_http_complex_value(r, location_conf->filter, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ngx_http_complex_value != NGX_OK"); goto unbind; }
            filter = ngx_pnalloc(r->pool, value.len + 1);
            if (!filter) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto unbind; }
            (void) ngx_cpystrn(filter, value.data, value.len + 1);
        }
        u_char **attrs = NULL;
        if (location_conf->attrs && location_conf->attrs->nelts) {
            if (!(attrs = ngx_pnalloc(r->pool, sizeof(u_char *) * (location_conf->attrs->nelts + 1)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto unbind; }
            ngx_http_auth_basic_ldap_attr_t *elt = location_conf->attrs->elts;
            for (ngx_uint_t i = 0; i < location_conf->attrs->nelts; i++) {
                if (!(attrs[i] = ngx_pnalloc(r->pool, elt[i].attr.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto unbind; }
                (void) ngx_cpystrn(attrs[i], elt[i].attr.data, elt[i].attr.len + 1);
            }
            attrs[location_conf->attrs->nelts] = NULL;
        }
        u_char *base = ngx_pnalloc(r->pool, location_conf->base.len + 1);
        if (!base) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto unbind; }
        (void) ngx_cpystrn(base, location_conf->base.data, location_conf->base.len + 1);
        if ((rc = ldap_search_ext_s(ld, (const char *)base, LDAP_SCOPE_SUBTREE, (const char *)filter, (char **)attrs, 0, NULL, NULL, NULL, 0, &msg)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_search_ext_s failed: %s: %s", ldap_err2string(rc), filter); goto msgfree; }
        if ((rc = ldap_count_entries(ld, msg)) <= 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_count_entries failed: %i", rc); goto msgfree; }
        for (LDAPMessage *entry = ldap_first_entry(ld, msg); entry; entry = ldap_next_entry(ld, entry)) {
            BerElement *ber;
            for (char *attr = ldap_first_attribute(ld, entry, &ber); attr; ldap_memfree(attr), attr = ldap_next_attribute(ld, entry, ber)) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: attr = %s", attr);
                struct berval **vals = ldap_get_values_len(ld, entry, attr);
                if (!vals) continue;
                int cnt = ldap_count_values_len(vals);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: ldap_count_values = %i", cnt);
                ngx_str_t key;
                key.len = ngx_strlen(attr);
#if (NGX_PCRE)
                ngx_http_auth_basic_ldap_attr_t *elt = NULL;
                if (location_conf->attrs && location_conf->attrs->nelts) {
                    ngx_http_auth_basic_ldap_attr_t *elts = location_conf->attrs->elts;
                    for (ngx_uint_t i = 0; i < location_conf->attrs->nelts; i++) if (elts[i].http_regex && elts[i].attr.len == key.len && !ngx_strncasecmp(elts[i].attr.data, (u_char *)attr, key.len)) { elt = &elts[i]; break; }
                }
#endif
                if (location_conf->header.len){
                    key.len += location_conf->header.len;
                    if (!(key.data = ngx_pnalloc(r->pool, key.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    ngx_snprintf(key.data, key.len, "%V%s", &location_conf->header, attr);
                } else {
                    if (!(key.data = ngx_pnalloc(r->pool, key.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    ngx_memcpy(key.data, attr, key.len);
                }
                for (int i = 0; i < cnt; i++) {
                    struct berval *val = vals[i];
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: vals[%i] = %*.s", i, (int)val->bv_len, val->bv_val);
                    ngx_str_t value;
                    value.len = val->bv_len;
                    if (!(value.data = ngx_pnalloc(r->pool, value.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    ngx_memcpy(value.data, val->bv_val, value.len);
#if (NGX_PCRE)
                    if (elt) {
                        if (ngx_http_regex_exec(r, elt->http_regex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                        if (ngx_http_complex_value(r, &elt->complex_value, &value) != NGX_OK) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    }
#endif
                    ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers);
                    if (!h) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    h->key = key;
                    h->value = value;
                }
                ldap_value_free_len(vals);
            }
            ber_free(ber, 0);
        }
        ldap_msgfree(msg);
    }
    if ((rc = ldap_unbind_ext_s(ld, NULL, NULL)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_unbind_ext_s failed: %s", ldap_err2string(rc)); }
    return NGX_OK;
msgfree:
    ldap_msgfree(msg);
unbind:
    if ((rc = ldap_unbind_ext_s(ld, NULL, NULL)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_unbind_ext_s failed: %s", ldap_err2string(rc)); }
ret:
    return ngx_http_auth_basic_ldap_set_realm(r, &location_conf->realm);
}

static ngx_int_t ngx_http_auth_basic_ldap_postconfiguration(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (!h) return NGX_ERROR;
    *h = ngx_http_auth_basic_ldap_handler;
    return NGX_OK;
}

static void *ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_location_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_ldap_location_conf_t));
    if (!conf) return NULL;
    conf->attrs = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_basic_ldap_location_conf_t *prev = parent;
    ngx_http_auth_basic_ldap_location_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->realm, prev->realm, "off");
    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_str_value(conf->bind, prev->bind, "");
    ngx_conf_merge_str_value(conf->base, prev->base, "");
    ngx_conf_merge_str_value(conf->header, prev->header, "");
    if (!conf->filter) conf->filter = prev->filter;
    ngx_conf_merge_ptr_value(conf->attrs, prev->attrs, NULL);
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
