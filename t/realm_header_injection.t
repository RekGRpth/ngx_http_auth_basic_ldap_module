# vi:ft=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: a quote in a realm built from a request variable cannot break out of the quoted value
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
        auth_basic_ldap_realm "R$arg_x";
    }
--- raw_request eval
"GET /t?x=evil\"injected HTTP/1.1\r
Host: localhost\r
Connection: close\r
\r
"
--- error_code: 401
--- response_headers_like
WWW-Authenticate: ^Basic realm="[^"]*"$


=== TEST 2: a safe realm value passes through unchanged
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
        auth_basic_ldap_realm "R$arg_x";
    }
--- request
GET /t?x=safevalue
--- error_code: 401
--- response_headers
WWW-Authenticate: Basic realm="Rsafevalue"
