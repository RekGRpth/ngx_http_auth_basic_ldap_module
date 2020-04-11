# Directives

#### auth_basic_ldap_attr
>Syntax: **auth_basic_ldap_attr** *string* | *string* *regexp* *result*;
>
>Default: -
>
>Context: main, server, location

Filter attributes by string, changing regexp to result and put it to input header (with prefix if specified)
>auth_basic_ldap_attr memberOf CN=Some1(\w+),CN=Users,DC=dc1,DC=dc2,DC=dc3 $1;

#### auth_basic_ldap_bind
>Syntax: **auth_basic_ldap_bind** *complex*;
>
>Default: -
>
>Context: main, server, location

Bind
>auth_basic_ldap_bind $remote_user@dc1.dc2.dc3;

#### auth_basic_ldap_header
>Syntax: **auth_basic_ldap_header** *complex*;
>
>Default: -
>
>Context: main, server, location

Prefix
>auth_basic_ldap_header LDAP-;

#### auth_basic_ldap_realm
>Syntax: **auth_basic_ldap_realm** *complex*;
>
>Default: -
>
>Context: main, server, location

Realm
>auth_basic_ldap_realm Autorization;

#### auth_basic_ldap_url
>Syntax: **auth_basic_ldap_url** *complex*;
>
>Default: -
>
>Context: main, server, location

Url
>auth_basic_ldap_url ldap://127.0.0.1/DC=dc1,DC=dc2,DC=dc3?memberOf,displayName,mail?sub?(&(uid=$remote_user)(memberOf=CN=Some1Some2,CN=Users,DC=dc1,DC=dc2,DC=dc3));
