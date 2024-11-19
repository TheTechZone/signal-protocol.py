from signal_protocol import net


def test_basic_auth():
    alice_auth = net.Auth("alice", "password")
    assert alice_auth.username() == b"alice"
    assert alice_auth.password() == b"password"

    assert alice_auth.as_http_header() == (
        "authorization",
        "Basic YWxpY2U6cGFzc3dvcmQ=",
    )
