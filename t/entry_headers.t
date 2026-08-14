# vi:ft=
#
# Exercises the code paths that need a real successful LDAP bind + search
# response to reach: ngx_http_auth_basic_ldap_bind(), read_handler()'s
# LDAP_RES_SEARCH_ENTRY dispatch, and ngx_http_auth_basic_ldap_search_entry()
# (attribute -> header conversion, the auth_basic_ldap_attr regex rewrite,
# and the zero-attribute-entry ber_free guard). No real LDAP server is
# available in CI, so t/ldap_mock.py stands in: a hand-rolled BER responder
# validated independently against libldap in the same session that wrote it.

use lib 'lib';
use Test::Nginx::Socket;
use File::Basename;
use Cwd 'abs_path';

my $mock = abs_path(dirname(__FILE__) . "/ldap_mock.py");
my @pids;
for my $spec ([18300, "normal"], [18301, "noattrs"], [18302, "crlf"]) {
    my ($port, $mode) = @$spec;
    my $pid = fork();
    if (!defined $pid) {
        die "fork failed: $!";
    }
    if ($pid == 0) {
        open(STDOUT, ">", "/dev/null");
        exec("python3", $mock, $port, $mode) or exit(1);
    }
    push @pids, $pid;
}
select(undef, undef, undef, 0.3);

END {
    local $?;
    kill "TERM", @pids if @pids;
    waitpid($_, 0) for @pids;
}

plan tests => repeat_each() * 2 * blocks();

no_long_string();

run_tests();

__DATA__

=== TEST 1: a successful bind+search delivers attributes as headers, auth_basic_ldap_attr rewrite applies
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:18300/dc=example,dc=com?cn,mail?sub?(cn=$remote_user)";
        auth_basic_ldap_header "X-";
        auth_basic_ldap_attr mail (\w+)@example\.com $1;
        echo "cn=$http_x_cn mail=$http_x_mail";
    }
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- request
GET /t
--- error_code: 200
--- response_body
cn=user mail=user


=== TEST 2: a search entry with zero attributes does not crash the worker (ber_free guard)
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:18301/dc=example,dc=com?cn?sub?(cn=$remote_user)";
        echo "reached content phase";
    }
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- request
GET /t
--- error_code: 200
--- response_body
reached content phase


=== TEST 3: an attribute value containing CR/LF is sanitized before becoming a header
--- main_config
    load_module /etc/nginx/modules/ngx_http_auth_basic_ldap_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location = /t {
        auth_basic_ldap_bind "cn=$remote_user,dc=example,dc=com";
        auth_basic_ldap_url "ldap://127.0.0.1:18302/dc=example,dc=com?cn,info?sub?(cn=$remote_user)";
        auth_basic_ldap_header "X-";
        echo "info=[$http_x_info]";
    }
--- more_headers
Authorization: Basic dXNlcjpwYXNz
--- request
GET /t
--- error_code: 200
--- response_body
info=[line1  line2]
