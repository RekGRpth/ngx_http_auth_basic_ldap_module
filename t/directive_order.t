# vi:ft=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 6;

no_long_string();

run_tests();

__DATA__

=== TEST 1: auth_basic_ldap_bind inherited from the server context is honored
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
    location = /t {
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic dXNlcjo=
--- request
GET /t
--- error_code: 401
--- error_log
empty password


=== TEST 2: auth_basic_ldap_url with no auth_basic_ldap_bind anywhere fails to start with a clear error
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- request
GET /t
--- must_die
--- error_log
no "auth_basic_ldap_bind" is defined for "auth_basic_ldap_url"


=== TEST 3: auth_basic_ldap_url declared before auth_basic_ldap_bind in the same location works
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
    }
--- more_headers
Authorization: Basic dXNlcjo=
--- request
GET /t
--- error_code: 401
--- error_log
empty password
