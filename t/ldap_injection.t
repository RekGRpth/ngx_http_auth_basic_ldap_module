# vi:ft=

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 11;

no_long_string();

run_tests();

__DATA__

=== TEST 1: username with a filter metacharacter ")" is rejected before contacting LDAP
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic YSliOnBhc3M=
--- request
GET /t
--- error_code: 401
--- error_log
unsafe character in username
--- no_error_log
ldap_sasl_bind


=== TEST 2: username with a DN metacharacter "," is rejected before contacting LDAP
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic YSxiOnBhc3M=
--- request
GET /t
--- error_code: 401
--- error_log
unsafe character in username
--- no_error_log
ldap_sasl_bind


=== TEST 3: username with a backslash is rejected before contacting LDAP
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic YVxiOnBhc3M=
--- request
GET /t
--- error_code: 401
--- error_log
unsafe character in username
--- no_error_log
ldap_sasl_bind


=== TEST 4: a safe username (control) still reaches the LDAP bind
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:1/dc=example,dc=com?cn?sub?(cn=$remote_user)";
    }
--- more_headers
Authorization: Basic am9obi5kb2U6cGFzcw==
--- request
GET /t
--- error_code: 500
--- no_error_log
unsafe character in username
