#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test FIBRE's archive protocol identity and block relay without a height prefix."""

from contextlib import contextmanager
import socket
import time

from test_framework.crypto.poly1305 import Poly1305
from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


SYN = 0
KEEPALIVE = 1
DISCONNECT = 2
PING = 5
PONG = 6
TX_CONTENTS = 7  # Reserved; unsupported even after a successful handshake.
# Minimum/current version advertised by origin/archive (65e12faf7c).
VERSION = (4 << 16) | 4
LOCAL_SECRET = "fibre-test-local"
REMOTE_SECRET = "fibre-test-remote"


class FibrePeer:
    """A UDP peer using FIBRE's checksum and packet obfuscation."""

    def __init__(self, sock, timeout, *, local_secret=LOCAL_SECRET, remote_secret=REMOTE_SECRET):
        self.sock = sock
        self.timeout = timeout
        self.send_key = hash256(local_secret.encode())[:8] * 4
        self.recv_key = hash256(remote_secret.encode())[:8] * 4
        host, port = sock.getsockname()[:2]
        self.address = f"[{host}]:{port}" if sock.family == socket.AF_INET6 else f"{host}:{port}"

    def send(self, msg_type, payload=b""):
        body = bytes([msg_type]) + payload
        tag = Poly1305(self.send_key).tag(body)
        self.sock.send(tag + bytes(value ^ tag[i % 8] for i, value in enumerate(body)))

    def receive_packet(self):
        packet = self.sock.recv(2048)
        assert len(packet) >= 17
        tag = packet[:16]
        body = bytes(value ^ tag[i % 8] for i, value in enumerate(packet[16:]))
        assert_equal(Poly1305(self.recv_key).tag(body), tag)
        return body[0] & 0x3f, body[1:]

    def receive(self, expected_type):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.001, deadline - time.monotonic()))
            msg_type, payload = self.receive_packet()
            if msg_type == expected_type:
                return payload
            assert msg_type != DISCONNECT, "Unexpected FIBRE disconnect"
            if msg_type == PING:
                self.send(PONG, payload)
        raise AssertionError(f"No FIBRE message of type {expected_type}")

    def check_syn(self):
        assert_equal(self.receive(SYN), VERSION.to_bytes(8, "little"))

    def handshake(self, version=VERSION):
        self.send(SYN, version.to_bytes(8, "little"))
        assert_equal(self.receive(KEEPALIVE), b"")
        self.send(KEEPALIVE)
        self.ping()

    def ping(self):
        nonce = b"fibre-v4"
        self.send(PING, nonce)
        assert_equal(self.receive(PONG), nonce)
