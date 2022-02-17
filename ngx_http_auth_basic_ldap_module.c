#include <ngx_http.h>

#include <ldap.h>

typedef struct {
    ngx_str_t attr;
#if (NGX_PCRE)
    ngx_http_complex_value_t cv;
    ngx_http_regex_t *http_regex;
#endif
} ngx_http_auth_basic_ldap_attr_t;

typedef struct {
    ngx_array_t *attrs;
    ngx_http_complex_value_t *bind;
    ngx_http_complex_value_t *header;
    ngx_http_complex_value_t *realm;
    ngx_http_complex_value_t *url;
} ngx_http_auth_basic_ldap_loc_conf_t;

typedef struct {
    ngx_flag_t enable;
} ngx_http_auth_basic_ldap_main_conf_t;

typedef struct {
    int msgid;
    LDAP *ldap;
    LDAPMessage *result;
    LDAPURLDesc *lud;
    ngx_connection_t *connection;
    ngx_int_t rc;
    ngx_str_t realm;
} ngx_http_auth_basic_ldap_ctx_t;

ngx_module_t ngx_http_auth_basic_ldap_module;

static char *ngx_http_auth_basic_ldap_attr_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_basic_ldap_loc_conf_t *location = conf;
    ngx_http_auth_basic_ldap_attr_t *attr;
    if (location->attrs == NGX_CONF_UNSET_PTR && !(location->attrs = ngx_array_create(cf->pool, 1, sizeof(*attr)))) return "!ngx_array_create";
    if (!(attr = ngx_array_push(location->attrs))) return "!ngx_array_push";
    ngx_memzero(attr, sizeof(*attr));
    ngx_str_t *elts = cf->args->elts;
    attr->attr = elts[1];
#if (NGX_PCRE)
    if (cf->args->nelts <= 2) return NGX_CONF_OK;
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t err = {sizeof(errstr), errstr};
    ngx_regex_compile_t rc;
    ngx_memzero(&rc, sizeof(rc));
    rc.pattern = elts[2];
    rc.options = NGX_REGEX_CASELESS;
    rc.err = err;
    if (!(attr->http_regex = ngx_http_regex_compile(cf, &rc))) return "!ngx_http_regex_compile";
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &elts[3];
    ccv.complex_value = &attr->cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
#endif
    return NGX_CONF_OK;
}

static char *ngx_http_set_complex_value_slot_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_basic_ldap_loc_conf_t *location = conf;
    if (!location->bind) return "!bind";
    ngx_http_auth_basic_ldap_main_conf_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_basic_ldap_module);
    main->enable = 1;
    return ngx_http_set_complex_value_slot(cf, cmd, conf);
}


static ngx_command_t ngx_http_auth_basic_ldap_commands[] = {
  { .name = ngx_string("auth_basic_ldap_attr"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1
#if (NGX_PCRE)
    |NGX_CONF_TAKE3
#endif
    ,
    .set = ngx_http_auth_basic_ldap_attr_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, attrs),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_bind"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, bind),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_header"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, header),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_realm"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, realm),
    .post = NULL },
  { .name = ngx_string("auth_basic_ldap_url"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_set_complex_value_slot_enable,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_http_auth_basic_ldap_loc_conf_t, url),
    .post = NULL },
    ngx_null_command
};

static ngx_int_t ngx_http_auth_basic_ldap_set_realm(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    ngx_str_t value = {sizeof("Basic realm=\"\"") - 1 + context->realm.len, NULL};
    if (!(value.data = ngx_pnalloc(r->pool, value.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (!(r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_list_push"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *p = ngx_copy(value.data, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_copy(p, context->realm.data, context->realm.len);
    *p = '"';
    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value = value;
    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_basic_ldap_bind(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (!context->lud->lud_dn) return NGX_AGAIN;
    int rc = ldap_search_ext(context->ldap, context->lud->lud_dn, context->lud->lud_scope, context->lud->lud_filter, context->lud->lud_attrs, 0, NULL, NULL, NULL, 0, &context->msgid);
    if (rc != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_search_ext != LDAP_SUCCESS and %s", ldap_err2string(rc)); return ngx_http_auth_basic_ldap_set_realm(r); }
    return NGX_AGAIN;
}

static ngx_int_t ngx_http_auth_basic_ldap_search_entry(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    BerElement *ber = NULL;
    char *attr = NULL;
    struct berval **vals = NULL;
    int ce = ldap_count_entries(context->ldap, context->result);
    ngx_int_t rc = NGX_OK;
    if (ce <= 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_count_entries <= 0 and %i", ce); goto ngx_http_auth_basic_ldap_set_realm; }
    ngx_http_auth_basic_ldap_loc_conf_t *location = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    ngx_str_t header = ngx_null_string;
    if (location->header && ngx_http_complex_value(r, location->header, &header) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_http_complex_value"); goto rc_NGX_ERROR; }
    for (LDAPMessage *entry = ldap_first_entry(context->ldap, context->result); entry; entry = ldap_next_entry(context->ldap, entry)) {
        for (attr = ldap_first_attribute(context->ldap, entry, &ber); attr; ldap_memfree(attr), attr = ldap_next_attribute(context->ldap, entry, ber)) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "attr = %s", attr);
            if (!(vals = ldap_get_values_len(context->ldap, entry, attr))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!ldap_get_values_len"); goto ngx_http_auth_basic_ldap_set_realm; }
            int cnt = ldap_count_values_len(vals);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap_count_values = %i", cnt);
            ngx_str_t key;
            key.len = ngx_strlen(attr) + header.len;
#if (NGX_PCRE)
            ngx_http_auth_basic_ldap_attr_t *elt = NULL;
            if (location->attrs != NGX_CONF_UNSET_PTR && location->attrs->nelts) {
                ngx_http_auth_basic_ldap_attr_t *elts = location->attrs->elts;
                for (ngx_uint_t i = 0; i < location->attrs->nelts; i++) if (elts[i].http_regex && elts[i].attr.len == key.len - header.len && !ngx_strncasecmp(elts[i].attr.data, (u_char *)attr, key.len - header.len)) { elt = &elts[i]; break; }
            }
#endif
            if (!(key.data = ngx_pnalloc(r->pool, key.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!ngx_pnalloc"); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR; }
            if (header.len) ngx_memcpy(key.data, header.data, header.len);
            ngx_memcpy(key.data + header.len, attr, key.len - header.len);
            for (int i = 0; i < cnt; i++) {
                struct berval *val = vals[i];
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "vals[%i] = %*.s", i, (int)val->bv_len, val->bv_val);
                ngx_str_t value;
                value.len = val->bv_len;
                if (!(value.data = ngx_pnalloc(r->pool, value.len))) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!ngx_pnalloc"); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR; }
                ngx_memcpy(value.data, val->bv_val, value.len);
#if (NGX_PCRE)
                if (elt) {
                    switch (ngx_http_regex_exec(r, elt->http_regex, &value)) {
                        case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_regex_exec == NGX_ERROR"); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR;
                        case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "skip: vals[%i] = %*.s", i, (int)val->bv_len, val->bv_val); continue;
                    }
                    if (ngx_http_complex_value(r, &elt->cv, &value) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR; }
                }
#endif
                ngx_table_elt_t *table_elt = ngx_list_push(&r->headers_in.headers);
                if (!table_elt) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!ngx_list_push"); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR; }
                table_elt->key = key;
                table_elt->value = value;
                table_elt->hash = 1;
            }
            ldap_value_free_len(vals);
        }
        ber_free(ber, 0);
    }
    return rc;
ngx_http_auth_basic_ldap_set_realm:
    rc = ngx_http_auth_basic_ldap_set_realm(r);
free:
    if (vals) ldap_value_free_len(vals);
    if (attr) ldap_memfree(attr);
    if (ber) ber_free(ber, 0);
    return rc;
rc_NGX_HTTP_INTERNAL_SERVER_ERROR:
    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    goto free;
rc_NGX_ERROR:
    rc = NGX_ERROR;
    goto free;
}

static void ngx_http_auth_basic_ldap_read_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (context->rc != NGX_AGAIN) return;
    char *errmsg = NULL;
    struct timeval timeout = {0, 0};
    int rc = ldap_result(context->ldap, context->msgid, 0, &timeout, &context->result);
    if (!rc) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ldap_result = 0"); goto ngx_http_core_run_phases; }
    if (rc < 0) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_result < 0 and %s", ldap_err2string(rc)); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR; }
    int errcode;
    switch ((rc = ldap_parse_result(context->ldap, context->result, &errcode, NULL, &errmsg, NULL, NULL, 0))) {
        case LDAP_SUCCESS: case LDAP_NO_RESULTS_RETURNED: break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_parse_result != LDAP_SUCCESS and %s", ldap_err2string(rc)); goto rc_NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (errcode != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s [%s]", ldap_err2string(errcode), errmsg ? errmsg : "-"); goto ngx_http_auth_basic_ldap_set_realm; }
    switch ((rc = ldap_msgtype(context->result))) {
        case LDAP_RES_BIND: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP_RES_BIND"); context->rc = ngx_http_auth_basic_ldap_bind(r); break;
        case LDAP_RES_SEARCH_ENTRY: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP_RES_SEARCH_ENTRY"); context->rc = ngx_http_auth_basic_ldap_search_entry(r); break;
        case LDAP_RES_SEARCH_REFERENCE: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_SEARCH_REFERENCE"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_SEARCH_RESULT: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP_RES_SEARCH_RESULT"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_MODIFY: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_MODIFY"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_ADD: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_ADD"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_DELETE: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_DELETE"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_MODDN: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_MODDN"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_COMPARE: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_COMPARE"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_EXTENDED: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_EXTENDED"); goto ngx_http_auth_basic_ldap_set_realm;
        case LDAP_RES_INTERMEDIATE: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP_RES_INTERMEDIATE"); goto ngx_http_auth_basic_ldap_set_realm;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unknown ldap_msgtype %d", rc); goto ngx_http_auth_basic_ldap_set_realm;
    }
ngx_http_core_run_phases:
    if (ngx_handle_read_event(ev, 0) != NGX_OK) context->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (errmsg) ldap_memfree(errmsg);
    if (context->rc != NGX_AGAIN) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Waking authentication request \"%V\"", &r->request_line); ngx_http_core_run_phases(r); }
    return;
ngx_http_auth_basic_ldap_set_realm:
    context->rc = ngx_http_auth_basic_ldap_set_realm(r);
    goto ngx_http_core_run_phases;
rc_NGX_HTTP_INTERNAL_SERVER_ERROR:
    context->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    goto ngx_http_core_run_phases;
}

static void ngx_http_auth_basic_ldap_write_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (context->rc != NGX_AGAIN) return;
    if (ngx_handle_write_event(ev, 0) != NGX_OK) context->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (context->rc != NGX_AGAIN) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Waking authentication request \"%V\"", &r->request_line); ngx_http_core_run_phases(r); }
}

static ngx_int_t ngx_http_auth_basic_ldap_context(ngx_http_request_t *r) {
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    ngx_str_set(&context->realm, "Authenticate");
    ngx_http_auth_basic_ldap_loc_conf_t *location = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    if (location->realm && ngx_http_complex_value(r, location->realm, &context->realm) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    if (context->realm.len == sizeof("off") - 1 && ngx_strncasecmp(context->realm.data, (u_char *)"off", sizeof("off") - 1) == 0) return NGX_DECLINED;
    if (ngx_http_auth_basic_user(r) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_auth_basic_user != NGX_OK"); return ngx_http_auth_basic_ldap_set_realm(r); }
    ngx_str_t url;
    if (ngx_http_complex_value(r, location->url, &url) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    u_char *urlc = ngx_pnalloc(r->pool, url.len + 1);
    if (!urlc) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    (void) ngx_cpystrn(urlc, url.data, url.len + 1);
    int rc;
    if ((rc = ldap_url_parse((const char *)urlc, &context->lud)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_url_parse != LDAP_SUCCESS and %s", ldap_err2string(rc)); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *p = ngx_snprintf(url.data, url.len, "%s://%s:%d/", context->lud->lud_scheme, context->lud->lud_host, context->lud->lud_port);
    *p = '\0';
    url.len = p - url.data;
    ngx_str_t bind;
    if (ngx_http_complex_value(r, location->bind, &bind) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
    u_char *dn = ngx_pnalloc(r->pool, bind.len + 1);
    if (!dn) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    (void) ngx_cpystrn(dn, bind.data, bind.len + 1);
    if ((rc = ldap_initialize(&context->ldap, (const char *)url.data)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_initialize(%V) != LDAP_SUCCESS and %s", &url, ldap_err2string(rc)); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    struct berval cred = {r->headers_in.passwd.len, (char *)r->headers_in.passwd.data};
    if ((rc = ldap_sasl_bind(context->ldap, (const char *)dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &context->msgid)) != LDAP_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_sasl_bind != LDAP_SUCCESS and %s", ldap_err2string(rc)); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    int fd;
    if (ldap_get_option(context->ldap, LDAP_OPT_DESC, &fd) != LDAP_OPT_SUCCESS) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ldap_get_option != LDAP_OPT_SUCCESS"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    if (!(context->connection = ngx_get_connection(fd, r->connection->log))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_get_connection"); return NGX_ERROR; }
    context->connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    context->connection->data = r;
    context->connection->log_error = r->connection->log_error;
    context->connection->read->handler = ngx_http_auth_basic_ldap_read_handler;
    context->connection->read->log = r->connection->log;
    context->connection->shared = 1;
    context->connection->start_time = ngx_current_msec;
    context->connection->write->handler = ngx_http_auth_basic_ldap_write_handler;
    context->connection->write->log = r->connection->log;
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(context->connection) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_conn != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_add_conn"); }
    } else {
        if (ngx_add_event(context->connection->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_add_event(read)"); }
        if (ngx_add_event(context->connection->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_add_event(write)"); }
    }
    return NGX_AGAIN;
}

static ngx_int_t ngx_http_auth_basic_ldap_handler(ngx_http_request_t *r) {
    ngx_http_auth_basic_ldap_loc_conf_t *location = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_ldap_module);
    if (!location->url) return NGX_DECLINED;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_auth_basic_ldap_ctx_t *context = ngx_http_get_module_ctx(r, ngx_http_auth_basic_ldap_module);
    if (!context) {
        if (!(context = ngx_pcalloc(r->pool, sizeof(*context)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        ngx_http_set_ctx(r, context, ngx_http_auth_basic_ldap_module);
        context->rc = ngx_http_auth_basic_ldap_context(r);
    }
    if (context->rc != NGX_AGAIN) {
        if (context->lud) { ldap_free_urldesc(context->lud); context->lud = NULL; }
        if (context->result) { ldap_msgfree(context->result); context->result = NULL; }
        if (context->ldap) { ldap_unbind_ext(context->ldap, NULL, NULL); context->ldap = NULL; }
        if (context->connection) { ngx_close_connection(context->connection); context->connection = NULL; }
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s = %i", __func__, context->rc);
    return context->rc;
}

static ngx_int_t ngx_http_auth_basic_ldap_postconfiguration(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_main_conf_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_basic_ldap_module);
    if (!main->enable) return NGX_OK;
    ngx_http_core_main_conf_t *core_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *handler = ngx_array_push(&core_main_conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (!handler) return NGX_ERROR;
    *handler = ngx_http_auth_basic_ldap_handler;
    return NGX_OK;
}

static void *ngx_http_auth_basic_ldap_create_main_conf(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_main_conf_t *main = ngx_pcalloc(cf->pool, sizeof(*main));
    if (!main) return NULL;
    return main;
}

static void *ngx_http_auth_basic_ldap_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_basic_ldap_loc_conf_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) return NULL;
    location->attrs = NGX_CONF_UNSET_PTR;
    return location;
}

static char *ngx_http_auth_basic_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_basic_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_basic_ldap_loc_conf_t *conf = child;
    if (!conf->bind) conf->bind = prev->bind;
    if (!conf->header) conf->header = prev->header;
    if (!conf->realm) conf->realm = prev->realm;
    if (!conf->url) conf->url = prev->url;
    ngx_conf_merge_ptr_value(conf->attrs, prev->attrs, NGX_CONF_UNSET_PTR);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_auth_basic_ldap_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_auth_basic_ldap_postconfiguration,
    .create_main_conf = ngx_http_auth_basic_ldap_create_main_conf,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_auth_basic_ldap_create_loc_conf,
    .merge_loc_conf = ngx_http_auth_basic_ldap_merge_loc_conf
};

ngx_module_t ngx_http_auth_basic_ldap_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_auth_basic_ldap_ctx,
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
