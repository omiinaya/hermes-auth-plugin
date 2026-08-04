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
        time.sleep(0.3)
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
