# vi:ft=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 8;

no_long_string();

run_tests();

__DATA__

=== TEST 1: empty password is rejected before contacting LDAP (auth bypass fix)
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic dXNlcjo=
--- request
GET /t
--- error_code: 401
--- response_headers
WWW-Authenticate: Basic realm="Authenticate"
--- error_log
empty password
--- no_error_log
ldap_sasl_bind


=== TEST 2: non-empty password still reaches the LDAP bind (control for TEST 1)
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- request
GET /t
--- error_code: 500
--- no_error_log
empty password


=== TEST 3: missing Authorization header is unaffected by the fix
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- request
GET /t
--- error_code: 401
--- error_log
ngx_http_auth_basic_user != NGX_OK
