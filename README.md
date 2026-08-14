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

Inherited from the closest enclosing context (main, server, location) that sets it. Must be defined somewhere for every location that uses `auth_basic_ldap_url`, or the configuration is rejected at startup.

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

If the URL has no base DN (no path component, e.g. `ldap://127.0.0.1/`), a successful bind alone is treated as a successful authentication; no search is performed and no attributes are added as headers.

## Security notes

- A request with an empty password is rejected immediately, before any LDAP operation. This prevents an "unauthenticated bind" (RFC 4513 §5.1.2) from being accepted by the LDAP server as if it were a successful login for an arbitrary existing username.
- The username portion of the `Authorization: Basic` header is substituted directly into the bind DN (`auth_basic_ldap_bind`) and into the search filter (`auth_basic_ldap_url`). To prevent LDAP injection, a username containing `( ) * \ , + " < > ; =` or a NUL byte is rejected before it is used.
