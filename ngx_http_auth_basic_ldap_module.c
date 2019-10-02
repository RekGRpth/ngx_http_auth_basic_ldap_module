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
    ngx_url_t *url;
} ngx_http_auth_basic_ldap_location_conf_t;

typedef struct {
    char *errmsg;
    int msgid;
    LDAP *ldap;
    LDAPMessage *result;
    ngx_int_t rc;
    ngx_peer_connection_t peer_connection;
}  ngx_http_auth_basic_ldap_context_t;

ngx_module_t ngx_http_auth_basic_ldap_module;

static char *ngx_http_auth_basic_ldap_attr_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = conf;
    if (location_conf->attrs == NGX_CONF_UNSET_PTR && !(location_conf->attrs = ngx_array_create(cf->pool, 4, sizeof(ngx_http_auth_basic_ldap_attr_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_http_auth_basic_ldap_attr_t *attr = ngx_array_push(location_conf->attrs);
    if (!attr) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
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
    if (!(attr->http_regex = ngx_http_regex_compile(cf, &rc))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[3];
    ccv.complex_value = &attr->complex_value;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
#endif
    return NGX_CONF_OK;
}

static char *ngx_http_auth_basic_ldap_url_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = conf;
    if (location_conf->url != NGX_CONF_UNSET_PTR) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    if (!(location_conf->url = ngx_pcalloc(cf->pool, sizeof(ngx_url_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    u_char *url = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (!url) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    (void) ngx_cpystrn(url, value[1].data, value[1].len + 1);
    LDAPURLDesc *ludp;
    int rc = ldap_url_parse((const char *)url, &ludp);
    if (rc != LDAP_SUCCESS) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: ldap_url_parse failed: %s", ldap_err2string(rc)); return NGX_CONF_ERROR; }
    location_conf->url->url.data = (u_char *) ludp->lud_host;
    location_conf->url->url.len = ngx_strlen(ludp->lud_host);
    location_conf->url->default_port = ludp->lud_port;
    if (ngx_parse_url(cf->pool, location_conf->url) != NGX_OK) {
        if (location_conf->url->err) ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s in LDAP hostname \"%V\"", location_conf->url->err, &location_conf->url->url);
        else ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ldap: %s:%d", __FILE__, __LINE__);
        ldap_free_urldesc(ludp);
        return NGX_CONF_ERROR;
    }
    ldap_free_urldesc(ludp);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_auth_basic_ldap_commands[] = {
  { .name = ngx_string("auth_basic_ldap_realm"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_location_conf_t, realm),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_url"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_auth_basic_ldap_url_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
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
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!(r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    size_t len = sizeof("Basic realm=\"\"") - 1 + location_conf->realm.len;
    u_char *basic = ngx_pnalloc(r->pool, len);
    if (!basic) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, location_conf->realm.data, location_conf->realm.len);
    *p = '"';
    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;
    return NGX_HTTP_UNAUTHORIZED;
}

static void ngx_http_auth_basic_ldap_free_connection(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (context->result) ldap_msgfree(context->result);
    if (context->errmsg) ldap_memfree(context->errmsg);
    if (context->ldap) ldap_unbind_ext(context->ldap, NULL, NULL);
//    if (context->peer_connection.connection) ngx_free_connection(context->peer_connection.connection);
    if (context->rc == NGX_ERROR || context->rc > NGX_OK || r->header_only) ngx_http_finalize_request(r, context->rc); else ngx_http_core_run_phases(r);
}

static ngx_int_t ngx_http_auth_basic_ldap_search(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    u_char *filter = NULL;
    if (location_conf->filter) {
        ngx_str_t value;
        if (ngx_http_complex_value(r, location_conf->filter, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        if (!(filter = ngx_pnalloc(r->pool, value.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        (void) ngx_cpystrn(filter, value.data, value.len + 1);
    }
    u_char **attrs = NULL;
    if (location_conf->attrs && location_conf->attrs->nelts) {
        if (!(attrs = ngx_pnalloc(r->pool, sizeof(u_char *) * (location_conf->attrs->nelts + 1)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
        ngx_http_auth_basic_ldap_attr_t *elt = location_conf->attrs->elts;
        for (ngx_uint_t i = 0; i < location_conf->attrs->nelts; i++) {
            if (!(attrs[i] = ngx_pnalloc(r->pool, elt[i].attr.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
            (void) ngx_cpystrn(attrs[i], elt[i].attr.data, elt[i].attr.len + 1);
        }
        attrs[location_conf->attrs->nelts] = NULL;
    }
    u_char *base = ngx_pnalloc(r->pool, location_conf->base.len + 1);
    if (!base) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    (void) ngx_cpystrn(base, location_conf->base.data, location_conf->base.len + 1);
    int rc = ldap_search_ext(context->ldap, (const char *)base, LDAP_SCOPE_SUBTREE, (const char *)filter, (char **)attrs, 0, NULL, NULL, NULL, 0, &context->msgid);
    if (rc != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_search_ext failed: %s: %s", ldap_err2string(rc), filter); return NGX_ERROR; }
    return NGX_OK;
}

static ngx_int_t ngx_http_auth_basic_ldap_attrs(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    int rc = ldap_count_entries(context->ldap, context->result);
    if (rc <= 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_count_entries failed: %i", rc); return NGX_ERROR; }
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    for (LDAPMessage *entry = ldap_first_entry(context->ldap, context->result); entry; entry = ldap_next_entry(context->ldap, entry)) {
        BerElement *ber;
        for (char *attr = ldap_first_attribute(context->ldap, entry, &ber); attr; ldap_memfree(attr), attr = ldap_next_attribute(context->ldap, entry, ber)) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: attr = %s", attr);
            struct berval **vals = ldap_get_values_len(context->ldap, entry, attr);
            if (!vals) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
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
                if (!(key.data = ngx_pnalloc(r->pool, key.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                ngx_snprintf(key.data, key.len, "%V%s", &location_conf->header, attr);
            } else {
                if (!(key.data = ngx_pnalloc(r->pool, key.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                ngx_memcpy(key.data, attr, key.len);
            }
            for (int i = 0; i < cnt; i++) {
                struct berval *val = vals[i];
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: vals[%i] = %*.s", i, (int)val->bv_len, val->bv_val);
                ngx_str_t value;
                value.len = val->bv_len;
                if (!(value.data = ngx_pnalloc(r->pool, value.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                ngx_memcpy(value.data, val->bv_val, value.len);
#if (NGX_PCRE)
                if (elt) {
                    if (ngx_http_regex_exec(r, elt->http_regex, &value) != NGX_OK) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); continue; }
                    if (ngx_http_complex_value(r, &elt->complex_value, &value) != NGX_OK) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                }
#endif
                ngx_table_elt_t *h = ngx_list_push(&r->headers_in.headers);
                if (!h) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
                h->key = key;
                h->value = value;
            }
            ldap_value_free_len(vals);
        }
        ber_free(ber, 0);
    }
    return NGX_OK;
}

static void ngx_http_auth_basic_ldap_read_handler(ngx_event_t *ev) {
    int rc;
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (!context->ldap) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto ngx_http_auth_basic_ldap_free_connection; }
    struct timeval timeout = {0, 0};
    if ((rc = ldap_result(context->ldap, context->msgid, 0, &timeout, &context->result)) <= 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_result failed: %s", ldap_err2string(rc)); goto ngx_http_auth_basic_ldap_free_connection; }
    int errcode;
    switch ((rc = ldap_parse_result(context->ldap, context->result, &errcode, NULL, &context->errmsg, NULL, NULL, 0))) {
        case LDAP_SUCCESS: case LDAP_NO_RESULTS_RETURNED: break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_parse_result failed:  %s", ldap_err2string(rc)); goto ngx_http_auth_basic_ldap_free_connection;
    }
    switch ((rc = ldap_msgtype(context->result))) {
        case LDAP_RES_BIND: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_BIND");
            if (errcode != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: bind failed: %s [%s]", ldap_err2string(errcode), context->errmsg ? context->errmsg : "-"); goto ngx_http_auth_basic_ldap_free_connection; }
            ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
            if (location_conf->base.len) {
                if (ngx_http_auth_basic_ldap_search(r) != NGX_OK) goto ngx_http_auth_basic_ldap_free_connection;
            } else {
                context->rc = NGX_OK;
                ngx_http_auth_basic_ldap_free_connection(r);
            }
        } break;
        case LDAP_RES_SEARCH_ENTRY: {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_SEARCH_ENTRY");
            if (errcode != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: search failed: %s [%s]", ldap_err2string(errcode), context->errmsg ? context->errmsg : "-"); goto ngx_http_auth_basic_ldap_free_connection; }
            if (ngx_http_auth_basic_ldap_attrs(r) != NGX_OK) goto ngx_http_auth_basic_ldap_free_connection;
            context->rc = NGX_OK;
            ngx_http_auth_basic_ldap_free_connection(r);
        } break;
        case LDAP_RES_SEARCH_REFERENCE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_SEARCH_REFERENCE"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_SEARCH_RESULT: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_SEARCH_RESULT"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_MODIFY: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_MODIFY"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_ADD: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_ADD"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_DELETE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_DELETE"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_MODDN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_MODDN"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_COMPARE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_COMPARE"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_EXTENDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_EXTENDED"); goto ngx_http_auth_basic_ldap_free_connection;
        case LDAP_RES_INTERMEDIATE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap: LDAP_RES_INTERMEDIATE"); goto ngx_http_auth_basic_ldap_free_connection;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: unknown ldap_msgtype %d", rc); goto ngx_http_auth_basic_ldap_free_connection;
    }
    return;
ngx_http_auth_basic_ldap_free_connection:
    context->rc = ngx_http_auth_basic_ldap_set_realm(r);
    ngx_http_auth_basic_ldap_free_connection(r);
}

static void ngx_http_auth_basic_ldap_write_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (!context->ldap) {
        int rc = ldap_init_fd(c->fd, LDAP_PROTO_TCP, NULL, &context->ldap);
        if (rc != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_init_fd failed: %s", ldap_err2string(rc)); goto ngx_http_auth_basic_ldap_free_connection; }
        ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
        size_t len = r->headers_in.user.len + sizeof("@") - 1 + location_conf->bind.len;
        u_char *who = ngx_pnalloc(r->pool, len + 1);
        u_char *last = ngx_snprintf(who, len, "%V@%V", &r->headers_in.user, &location_conf->bind);
        if (last != who + len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); goto ngx_http_auth_basic_ldap_free_connection; }
        *last = '\0';
        struct berval cred = {r->headers_in.passwd.len, (char *)r->headers_in.passwd.data};
        if ((rc = ldap_sasl_bind(context->ldap, (const char *)who, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &context->msgid)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: ldap_sasl_bind failed: %s", ldap_err2string(rc)); goto ngx_http_auth_basic_ldap_free_connection; }
    }
    return;
ngx_http_auth_basic_ldap_free_connection:
    context->rc = ngx_http_auth_basic_ldap_set_realm(r);
    ngx_http_auth_basic_ldap_free_connection(r);
}

static ngx_int_t ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    if (location_conf->realm.len == sizeof("off") - 1 && ngx_strncasecmp(location_conf->realm.data, (u_char *)"off", sizeof("off") - 1) == 0) return NGX_DECLINED;
    switch (ngx_http_auth_basic_user(r)) {
        case NGX_DECLINED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: no user/password was provided for basic authentication"); return ngx_http_auth_basic_ldap_set_realm(r);
        case NGX_ERROR: return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!r->headers_in.passwd.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: no password was provided for basic authentication"); return ngx_http_auth_basic_ldap_set_realm(r); }
    ngx_http_auth_basic_ldap_context_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (context) return context->rc;
    context = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_basic_ldap_context_t));
    if (!context) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: %s:%d", __FILE__, __LINE__); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_addr_t *addr = &location_conf->url->addrs[ngx_random() % location_conf->url->naddrs];
    context->peer_connection.sockaddr = addr->sockaddr;
    context->peer_connection.socklen = addr->socklen;
    context->peer_connection.name = &addr->name;
    context->peer_connection.get = ngx_event_get_peer;
    context->peer_connection.log = r->connection->log;
    context->peer_connection.log_error = r->connection->log_error;
    ngx_int_t rc = ngx_event_connect_peer(&context->peer_connection);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (context->peer_connection.connection) ngx_close_connection(context->peer_connection.connection);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap: Unable to connect to LDAP server \"%V\"", &addr->name);
        return ngx_http_auth_basic_ldap_set_realm(r);
    }
    context->peer_connection.connection->log = r->connection->log;
    context->peer_connection.connection->log_error = r->connection->log_error;
    context->peer_connection.connection->read->handler = ngx_http_auth_basic_ldap_read_handler;
    context->peer_connection.connection->write->handler = ngx_http_auth_basic_ldap_write_handler;
    context->peer_connection.connection->read->log = r->connection->log;
    context->peer_connection.connection->write->log = r->connection->log;
    context->peer_connection.connection->data = r;
    context->rc = NGX_AGAIN;
    ngx_http_set_ctx(r, context, ngx_http_auth_basic_ldap_module);
    return context->rc;
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
    conf->url = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_basic_ldap_location_conf_t *prev = parent;
    ngx_http_auth_basic_ldap_location_conf_t *conf = child;
    ngx_conf_merge_str_value(conf->realm, prev->realm, "off");
    ngx_conf_merge_str_value(conf->bind, prev->bind, "");
    ngx_conf_merge_str_value(conf->base, prev->base, "");
    ngx_conf_merge_str_value(conf->header, prev->header, "");
    if (!conf->filter) conf->filter = prev->filter;
    ngx_conf_merge_ptr_value(conf->attrs, prev->attrs, NULL);
    ngx_conf_merge_ptr_value(conf->url, prev->url, NULL);
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
