#!/usr/bin/env python3
# Minimal hand-rolled LDAPv3 (RFC4511) responder used only by the test suite.
# Speaks just enough BER to answer one simple Bind + one Search with a
# single canned entry, so the "happy path" (bind -> search -> read attributes)
# in ngx_http_auth_basic_ldap_module.c can be exercised without a real LDAP
# server. Not a general-purpose LDAP implementation.

import socket
import sys
import threading


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def ber_tlv(tag, content):
    return bytes([tag]) + ber_len(len(content)) + content


def ber_int(n, tag=0x02):
    assert 0 <= n <= 127
    return ber_tlv(tag, bytes([n]))


def ber_str(s, tag=0x04):
    if isinstance(s, str):
        s = s.encode()
    return ber_tlv(tag, s)


def ber_seq(*parts, tag=0x30):
    return ber_tlv(tag, b"".join(parts))


def ldap_message(msgid, op):
    return ber_seq(ber_int(msgid), op)


def bind_response(msgid):
    # BindResponse ::= [APPLICATION 1] LDAPResult
    op = ber_tlv(0x61, ber_int(0) + ber_str("") + ber_str(""))
    return ldap_message(msgid, op)


def search_result_entry(msgid, dn, attrs):
    # attrs: list of (name, [values])
    partial_attrs = b""
    for name, vals in attrs:
        valset = ber_tlv(0x31, b"".join(ber_str(v) for v in vals))  # SET OF
        partial_attrs += ber_seq(ber_str(name), valset)
    op_body = ber_str(dn) + ber_seq(partial_attrs)
    op = ber_tlv(0x64, op_body)  # [APPLICATION 4]
    return ldap_message(msgid, op)


def search_result_done(msgid):
    op = ber_tlv(0x65, ber_int(0) + ber_str("") + ber_str(""))  # [APPLICATION 5]
    return ldap_message(msgid, op)


def read_full(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def read_ldap_message(sock):
    tag = read_full(sock, 1)
    length_byte = read_full(sock, 1)[0]
    if length_byte & 0x80:
        length = int.from_bytes(read_full(sock, length_byte & 0x7F), "big")
    else:
        length = length_byte
    read_full(sock, length)  # content, discarded: we don't need to parse the request


def handle_conn(conn, mode):
    try:
        read_ldap_message(conn)  # BindRequest
        conn.sendall(bind_response(1))
        read_ldap_message(conn)  # SearchRequest
        dn = "cn=user,dc=example,dc=com"
        if mode == "noattrs":
            attrs = []
        elif mode == "crlf":
            attrs = [("cn", ["user"]), ("info", ["line1\r\nline2"])]
        else:
            attrs = [("cn", ["user"]), ("mail", ["user@example.com"])]
        conn.sendall(search_result_entry(2, dn, attrs))
        conn.sendall(search_result_done(2))
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def main():
    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "normal"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn, mode), daemon=True).start()


if __name__ == "__main__":
    main()
