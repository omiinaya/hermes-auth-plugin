"""TCP wrapper edge cases for the handshake module.

The protocol state machine is covered in test_handshake.py; these tests
cover the run_handshake_server / run_handshake_client console wrappers:
connection-refused, wrong-peer rejection, rate limiting, server stop,
and socket timeouts.
"""

import socket
import threading
import time

import pytest

from hermes_id.handshake import (
    HandshakeError,
    HandshakeMessage,
    recv_message,
    run_handshake_client,
    run_handshake_server,
)


@pytest.fixture(scope="module")
def alice():
    from hermes_id.crypto import generate_keypair
    from hermes_id.identity import create_identity

    private, public = generate_keypair()
    card = create_identity(private, public, metadata={"name": "Alice"})
    return private, card


@pytest.fixture(scope="module")
def bob():
    from hermes_id.crypto import generate_keypair
    from hermes_id.identity import create_identity

    private, public = generate_keypair()
    card = create_identity(private, public, metadata={"name": "Bob"})
    return private, card


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_server(bob, port, **kw):
    bob_private, bob_card = bob
    stop_event = threading.Event()
    t = threading.Thread(
        target=lambda: run_handshake_server(
            bob_card, bob_private, host="127.0.0.1", port=port,
            stop_event=stop_event, **kw
        ),
        daemon=True,
    )
    t.start()
    time.sleep(0.3)
    return stop_event


class TestClientFailures:
    def test_connect_refused(self, alice, capsys):
        """Connecting to a dead port returns (False, None, None)."""
        alice_private, alice_card = alice
        port = _free_port()
        success, peer, key = run_handshake_client(
            alice_card, alice_private, peer_did="", host="127.0.0.1", port=port,
        )
        assert success is False
        assert peer is None
        assert key is None
        assert "Connection failed" in capsys.readouterr().out

    def test_wrong_peer_did_rejected(self, alice, bob, capsys):
        """Client expects peer A but the responder is B → auth fails."""
        alice_private, alice_card = alice
        bob_private, bob_card = bob
        port = _free_port()

        def on_verify(peer_card):
            # Reject every peer — this makes the responder abort
            return False

        stop = _start_server(bob, port, on_verify=on_verify)
        try:
            success, peer, key = run_handshake_client(
                alice_card, alice_private,
                peer_did=bob_card.id,  # expected DID (client-side)
                host="127.0.0.1", port=port,
            )
            # Server rejects the auth → client gets an error message
            assert success is False
        finally:
            stop.set()
            time.sleep(0.2)

    def test_client_socket_timeout(self, alice, capsys):
        """A peer that sends nothing triggers recv_message timeout."""
        alice_private, alice_card = alice
        port = _free_port()

        # A server that accepts but never responds
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(1.0)

        def accept_and_hold():
            try:
                conn, _ = srv.accept()
                time.sleep(5)  # hold the connection open, send nothing
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=accept_and_hold, daemon=True)
        t.start()
        try:
            success, peer, key = run_handshake_client(
                alice_card, alice_private, peer_did="",
                host="127.0.0.1", port=port,
            )
            assert success is False
        finally:
            srv.close()


class TestServerBehavior:
    def test_rate_limit_exceeded(self, alice, bob, capsys):
        """A server configured with rate_limit=1 drops the second conn."""
        alice_private, alice_card = alice
        bob_private, bob_card = bob
        port = _free_port()

        stop = _start_server(bob, port, rate_limit=1, rate_window=60.0)
        try:
            # First handshake succeeds
            ok1, _, _ = run_handshake_client(
                alice_card, alice_private, peer_did=bob_card.id,
                host="127.0.0.1", port=port,
            )
            # Second within the window — rate limited
            ok2, _, _ = run_handshake_client(
                alice_card, alice_private, peer_did=bob_card.id,
                host="127.0.0.1", port=port,
            )
            assert ok1 is True
            assert ok2 is False
            out = capsys.readouterr().out
            assert "Rate limit exceeded" in out
        finally:
            stop.set()
            time.sleep(0.2)

    def test_stop_event_stops_server(self, bob, capsys):
        """Setting stop_event exits the accept loop cleanly."""
        bob_private, bob_card = bob
        port = _free_port()
        stop = _start_server(bob, port)
        time.sleep(0.2)
        stop.set()
        # Accept has a 1s timeout — wait for the loop to notice the event
        time.sleep(1.5)
        out = capsys.readouterr().out
        assert "Server stopped" in out

    def test_server_bad_handshake_logs_error(self, alice, bob, capsys):
        """A malformed client connection logs 'Handshake failed'."""
        bob_private, bob_card = bob
        port = _free_port()
        stop = _start_server(bob, port)
        try:
            # Send garbage bytes instead of a handshake
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.sendall(b"garbage-not-a-handshake")
            s.close()
            time.sleep(0.5)
            out = capsys.readouterr().out
            assert "Handshake failed" in out or "Connection" in out
        finally:
            stop.set()
            time.sleep(0.2)


class TestRecvMessageErrors:
    def test_recv_timeout_raises(self):
        """recv_message on a silent socket raises HandshakeError."""
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        listener.settimeout(1.0)

        accepted = []

        def accept_and_hold():
            try:
                conn, _ = listener.accept()
                accepted.append(conn)
                time.sleep(3)  # accept but never send
            except Exception:
                pass

        t = threading.Thread(target=accept_and_hold, daemon=True)
        t.start()

        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        try:
            with pytest.raises(HandshakeError):
                recv_message(client, timeout=0.3)
        finally:
            client.close()
            listener.close()
            time.sleep(0.1)

    def test_recv_payload_timeout_raises(self):
        """A length prefix followed by a silent payload times out."""
        import struct

        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        listener.settimeout(1.0)

        def accept_and_partial():
            try:
                conn, _ = listener.accept()
                # Send the 4-byte length prefix claiming a big payload,
                # then go silent — payload read hits the timeout.
                conn.sendall(struct.pack("!I", 10))
                time.sleep(3)
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=accept_and_partial, daemon=True)
        t.start()

        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        try:
            with pytest.raises(HandshakeError):
                recv_message(client, timeout=0.3)
        finally:
            client.close()
            listener.close()
            time.sleep(0.1)


class TestServerInterrupt:
    def test_keyboard_interrupt_stops_cleanly(self, bob, capsys, monkeypatch):
        """KeyboardInterrupt inside the accept loop stops the server."""
        bob_private, bob_card = bob
        port = _free_port()

        # Replace socket.accept to raise KeyboardInterrupt once
        def interrupt_accept(self, *a, **kw):
            raise KeyboardInterrupt

        monkeypatch.setattr(socket.socket, "accept", interrupt_accept)
        run_handshake_server(
            bob_card, bob_private, host="127.0.0.1", port=port,
        )
        out = capsys.readouterr().out
        assert "Server stopped" in out


class TestClientAuthFailed:
    def test_client_auth_failure_returns_false(self, alice, bob, capsys):
        """A confirm that fails verification → client returns False via the
        is_authenticated check (not an exception path)."""
        from hermes_id.handshake import HandshakeProtocol, send_message

        alice_private, alice_card = alice
        bob_private, bob_card = bob
        port = _free_port()

        # A fake responder that completes the flow but sends a confirm
        # signed with the WRONG key, so client-side verification fails.
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(3.0)

        def serve_bad_confirm():
            try:
                conn, _ = srv.accept()
                # Real responder protocol
                hp = HandshakeProtocol(bob_card, bob_private, is_responder=True)
                hello_msg = recv_message(conn)
                challenge_msg = hp.handle_message(hello_msg)
                send_message(conn, challenge_msg)
                auth_msg = recv_message(conn)
                # Generate a genuine confirm...
                good = hp.handle_message(auth_msg)
                # ...then swap the signature with a bogus one
                from hermes_id.crypto import _b64

                bad_confirm = HandshakeMessage(
                    msg_type="confirm",
                    payload={**good.payload, "signature": _b64(b"X" * 64)},
                )
                send_message(conn, bad_confirm)
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=serve_bad_confirm, daemon=True)
        t.start()
        time.sleep(0.3)

        try:
            success, peer, key = run_handshake_client(
                alice_card, alice_private, peer_did="",
                host="127.0.0.1", port=port,
            )
            assert success is False
            out = capsys.readouterr().out
            assert "Authentication failed" in out
        finally:
            srv.close()


class TestServerFinalRecv:
    def test_server_ignores_final_recv_error(self, alice, bob, capsys):
        """A client that disconnects before the final ack is handled."""

        from hermes_id.handshake import HandshakeProtocol, send_message

        alice_private, alice_card = alice
        bob_private, bob_card = bob
        port = _free_port()
        stop = _start_server(bob, port)
        try:
            # Client does the first 3 steps then disconnects abruptly
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            hp = HandshakeProtocol(alice_card, alice_private, is_responder=False)
            send_message(s, hp.start())
            challenge_msg = recv_message(s)
            auth_msg = hp.handle_message(challenge_msg)
            send_message(s, auth_msg)
            confirm_msg = recv_message(s)
            final = hp.handle_message(confirm_msg)
            if final.msg_type != "error":
                send_message(s, final)
            s.close()  # abrupt close before server reads the final ack
            time.sleep(0.5)
            out = capsys.readouterr().out
            # The server either logs the successful handshake or swallows
            # the final-recv HandshakeError — either way it stays up.
            assert "Server stopped" not in out  # server still running
        finally:
            stop.set()
            time.sleep(0.3)

    def test_handle_connection_final_recv_error_swallowed(self, alice, bob, capsys):
        """_handle_connection swallows a HandshakeError on the final ack."""
        import hermes_id.handshake as hs_mod

        # Use a real socketpair so the responder's fresh protocol generates
        # its own challenge and the client signs it correctly.
        srv_sock, cli_sock = socket.socketpair()
        srv_sock.settimeout(3.0)
        cli_sock.settimeout(3.0)

        alice_private, alice_card = alice
        bob_private, bob_card = bob
        from hermes_id.handshake import send_message

        def run_server():
            try:
                hs_mod._handle_connection(srv_sock, bob_card, bob_private)
            except Exception as e:  # pragma: no cover — swallow must prevent this
                print(f"server raised: {e}")

        t = threading.Thread(target=run_server, daemon=True)
        t.start()

        # Client drives a real handshake, then disconnects before the final ack
        hp = hs_mod.HandshakeProtocol(alice_card, alice_private, is_responder=False)
        send_message(cli_sock, hp.start())
        challenge = hs_mod.recv_message(cli_sock)
        auth = hp.handle_message(challenge)
        send_message(cli_sock, auth)
        confirm = hs_mod.recv_message(cli_sock)
        assert confirm.payload.get("status") == "ok"
        # Do NOT send the final ack — just close, so the server's final
        # recv_message raises HandshakeError (connection closed).
        cli_sock.close()
        t.join(timeout=4)
        assert not t.is_alive()  # server thread finished without propagating
        srv_sock.close()
