# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Transport and session runners (Master Guide Appendix H.3 timers / H.6 cleanup semantics).

Provides:
- two run entries: listen (responder) and connect (initiator), with
  connection retry and a self-connection warning;
- an interactive chat session: receive thread + heartbeat thread +
  main-thread send loop;
- idempotent shutdown (Appendix H.6): the three thread exit paths are
  funneled into one place, so the socket is closed exactly once and the
  session key is wiped exactly once; otherwise a long-running session
  accumulates half-open sockets (FD leaks) and key residue.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from typing import Any, Dict, Optional

from .errors import SilentDropError, ISOSTRESSError, ISOSTRESSTimeoutError
from .frames import force_close_socket
from .handshake import (
    DATA_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    SILENT_DROP_HOLD,
    HandshakePeer,
)
from .params import TIME_WINDOW, ISOSTRESSParams
from .session import SecureSession

DEFAULT_PORT: int = 37291
DEFAULT_HOST_LISTEN: str = "0.0.0.0"
DEFAULT_HOST_CONNECT: str = "127.0.0.1"
DEFAULT_CONNECT_RETRY_COUNT: int = 3
DEFAULT_CONNECT_RETRY_INTERVAL: float = 5.0
HEARTBEAT_INTERVAL: float = 30.0  # Empty-payload heartbeat (Appendix G.5: baseline traffic + half-open detection)
HEARTBEAT_PAYLOAD: bytes = b""


def set_socket_options(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def _is_self_connection(host: str, port: int) -> bool:
    """Check whether the target address is the local host (covers localhost aliases and IPv6)."""
    try:
        local_ips: set = {"127.0.0.1", "0.0.0.0", "::1"}
        hostname = socket.gethostname()
        try:
            local_ips.update(socket.gethostbyname_ex(hostname)[2])
        except socket.gaierror:
            pass
        try:
            for info in socket.getaddrinfo(host, port):
                if info[4][0] in local_ips:
                    return True
        except socket.gaierror:
            pass
        return host in local_ips
    except Exception:
        return False


# =============================================================================
# Interactive chat session
# =============================================================================


class ChatSession:
    """Three-thread interactive session: receive / heartbeat / send. shutdown is idempotent (Appendix H.6)."""

    def __init__(self, session: SecureSession, sock: socket.socket) -> None:
        self.session = session
        self.sock = sock
        self._running = True
        self._print_lock = threading.Lock()
        self._recv_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._shutdown_lock = threading.Lock()
        self._shutdown_done = False

    def start(self) -> None:
        self._recv_thread = threading.Thread(
            target=self._recv_loop, daemon=True, name="isostress-recv"
        )
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="isostress-heartbeat"
        )
        self._recv_thread.start()
        self._heartbeat_thread.start()
        self._send_loop()

    # -- Send (main thread) ---------------------------------------------------
    def _send_loop(self) -> None:
        try:
            while self._running:
                try:
                    msg = input("> ")
                except EOFError:
                    break
                if not msg:
                    continue
                if msg.strip().lower() in ("/quit", "/exit", "/q"):
                    break
                try:
                    self.session.send_packet(self.sock, msg.encode("utf-8"))
                except ISOSTRESSError as e:
                    with self._print_lock:
                        print(f"\r[Send failed] {e}")
                    break
                except (ConnectionError, BrokenPipeError, OSError) as e:
                    with self._print_lock:
                        print(f"\r[Send failed] {e}")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    # -- Receive (thread) -----------------------------------------------------
    def _recv_loop(self) -> None:
        try:
            while self._running:
                try:
                    data = self.session.recv_packet(self.sock)
                except ISOSTRESSTimeoutError as e:
                    with self._print_lock:
                        print(f"\r[Timeout error] {e}")
                    break
                except (ConnectionError, OSError):
                    break
                except ISOSTRESSError as e:
                    with self._print_lock:
                        print(f"\r[Security error] {e}")
                    break
                if len(data) == 0:
                    continue  # Heartbeat / out-of-window packet: skip silently
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = repr(data)
                with self._print_lock:
                    print(f"\r[Peer] {text}\n> ", end="", flush=True)
        except (ConnectionError, OSError, ISOSTRESSError) as exc:
            if self._running:
                with self._print_lock:
                    print(f"\r[Error] {exc}\n> ", end="", flush=True)
        finally:
            self.shutdown()

    # -- Heartbeat (thread) -----------------------------------------------------
    def _heartbeat_loop(self) -> None:
        """Application-layer heartbeat: detects half-open connections and takes part in ratchet rotation (Appendix G.5)."""
        try:
            while self._running:
                time.sleep(HEARTBEAT_INTERVAL)
                if not self._running:
                    break
                try:
                    self.session.send_packet(self.sock, HEARTBEAT_PAYLOAD)
                except (ConnectionError, BrokenPipeError, OSError, ISOSTRESSError):
                    if self._running:
                        with self._print_lock:
                            print("\r[Heartbeat failed] connection may have been lost")
                        self.shutdown()
                    break
        except Exception as exc:
            if self._running:
                with self._print_lock:
                    print(f"\r[Heartbeat error] {exc}")
                self.shutdown()

    # -- Idempotent shutdown ---------------------------------------------------------
    def shutdown(self) -> None:
        """All three thread exit paths are funneled into one place: the socket is closed exactly once and the key is wiped exactly once."""
        with self._shutdown_lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
        self._running = False
        force_close_socket(self.sock)
        self.session.wipe()


# =============================================================================
# Listen / connect runners
# =============================================================================


def _print_params(args: Dict[str, Any]) -> None:
    params: ISOSTRESSParams = args["params"]
    print(
        f"    Parameters: random_len={params.random_len}, "
        f"rate={params.random_rate}, window={params.window}, "
        f"time_window={args.get('time_window', TIME_WINDOW)}"
    )


def run_listen(args: Dict[str, Any]) -> None:
    """Listen mode (responder). After a strict silent failure the connection is closed (H.3: close when the hold is exhausted)."""
    host, port = args["host"], args["port"]
    params: ISOSTRESSParams = args["params"]
    print(f"\n[+] Listening on {host}:{port} ...")
    _print_params(args)
    print("    Waiting for peer connection... (Ctrl+C to abort)")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    set_socket_options(server)
    conn: Optional[socket.socket] = None
    try:
        server.bind((host, port))
        server.listen(1)
        server.settimeout(None)
        try:
            conn, addr = server.accept()
        except KeyboardInterrupt:
            print("\n[+] Listening aborted.")
            return

        print(f"[+] Connection from {addr}")
        set_socket_options(conn)
        peer = HandshakePeer(
            args["psk_bytes"],
            params,
            role="responder",
            padding=args.get("padding"),
            jitter=args.get("jitter", 0.0),
            time_window=args.get("time_window", TIME_WINDOW),
            silent_hold=args.get("silent_hold", SILENT_DROP_HOLD),
        )
        try:
            material = peer.perform_handshake(conn)
        except SilentDropError as e:
            # The silent hold has been exhausted (or the peer has closed): closing now leaks no information (H.3)
            print(f"\n[!] {e}")
            force_close_socket(conn)
            return
        except ISOSTRESSError as e:
            print(f"\n[!] Handshake failed: {e}")
            print(
                "    Possible causes: PSK mismatch / parameter mismatch / network tampering"
            )
            force_close_socket(conn)
            return
        except (ConnectionError, OSError) as e:
            print(f"\n[!] Connection error: {e}")
            force_close_socket(conn)
            return

        print("[+] Handshake complete; secure channel established.")
        print("    Type a message and press Enter to send; /quit or Ctrl+C to exit\n")
        ChatSession(SecureSession(material), conn).start()
    except OSError as e:
        print(f"\n[!] Listen failed: {e}")
        print("    Possible causes: port in use / insufficient permissions")
        if conn is not None:
            force_close_socket(conn)
    finally:
        force_close_socket(server)


def run_connect(args: Dict[str, Any]) -> None:
    """Connect mode (initiator), with retries (Appendix B: 3 attempts by default, 5-second interval)."""
    host, port = args["host"], args["port"]
    params: ISOSTRESSParams = args["params"]
    max_retries = args.get("retry_count", DEFAULT_CONNECT_RETRY_COUNT)
    retry_interval = args.get("retry_interval", DEFAULT_CONNECT_RETRY_INTERVAL)

    print(f"\n[+] Connecting to {host}:{port} ...")
    _print_params(args)

    if _is_self_connection(host, port):
        print(f"  [!] Warning: target address {host} is a local address.")
        print(
            "    If isostress in listen mode is not running on this machine at the same time, the connection will fail.\n"
        )

    try:
        for attempt in range(1, max_retries + 1):
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_socket_options(conn)
            established = False
            try:
                if attempt > 1:
                    print(f"    Connection attempt {attempt}/{max_retries}...")
                conn.settimeout(HANDSHAKE_TIMEOUT)
                conn.connect((host, port))
                established = True
                # The handshake uses a 15 s timeout; the data phase restores 60 s (the 30 s heartbeat must be able to catch up)
                conn.settimeout(DATA_TIMEOUT)

                peer = HandshakePeer(
                    args["psk_bytes"],
                    params,
                    role="initiator",
                    padding=args.get("padding"),
                    jitter=args.get("jitter", 0.0),
                    time_window=args.get("time_window", TIME_WINDOW),
                    silent_hold=args.get("silent_hold", SILENT_DROP_HOLD),
                )
                try:
                    material = peer.perform_handshake(conn)
                except ISOSTRESSError as e:
                    print(f"\n[!] Handshake failed: {e}")
                    print(
                        "    Possible causes: PSK mismatch / parameter mismatch / network tampering"
                    )
                    force_close_socket(conn)
                    return
                except (ConnectionError, OSError) as e:
                    print(f"\n[!] Connection error: {e}")
                    force_close_socket(conn)
                    return

                print("[+] Handshake complete; secure channel established.")
                print(
                    "    Type a message and press Enter to send; /quit or Ctrl+C to exit\n"
                )
                ChatSession(SecureSession(material), conn).start()
                return
            except (ConnectionError, OSError) as e:
                if attempt < max_retries:
                    print(
                        f"    Connection failed: {e}; retrying in {retry_interval} s..."
                    )
                    time.sleep(retry_interval)
                else:
                    print(
                        f"\n[!] Connection failed; maximum retry count ({max_retries}) reached"
                    )
                    print(f"    Last error: {e}")
                if established:
                    force_close_socket(conn)
    except KeyboardInterrupt:
        print("\n[+] Connection aborted.")
        return


def run_session(args: Dict[str, Any]) -> None:
    """Session run entry point (invoked by the CLI)."""
    if args["role"] == "listen":
        run_listen(args)
    else:
        run_connect(args)
