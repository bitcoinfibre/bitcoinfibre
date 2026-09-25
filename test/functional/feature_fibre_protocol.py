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
# Minimum/current version advertised by origin/archive (65e12faf7c).
VERSION = (4 << 16) | 4
LOCAL_SECRET = "fibre-test-local"
REMOTE_SECRET = "fibre-test-remote"


class FibrePeer:
    """A UDP peer using FIBRE's checksum and packet obfuscation."""

    def __init__(self, sock, timeout):
        self.sock = sock
        self.timeout = timeout
        self.send_key = hash256(LOCAL_SECRET.encode())[:8] * 4
        self.recv_key = hash256(REMOTE_SECRET.encode())[:8] * 4
        self.address = f"127.0.0.1:{sock.getsockname()[1]}"

    def send(self, msg_type, payload=b""):
        body = bytes([msg_type]) + payload
        tag = Poly1305(self.send_key).tag(body)
        self.sock.send(tag + bytes(value ^ tag[i % 8] for i, value in enumerate(body)))

    def receive(self, expected_type):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.001, deadline - time.monotonic()))
            packet = self.sock.recv(2048)
            assert len(packet) >= 17
            tag = packet[:16]
            body = bytes(value ^ tag[i % 8] for i, value in enumerate(packet[16:]))
            assert_equal(Poly1305(self.recv_key).tag(body), tag)
            msg_type = body[0] & 0x3f
            if msg_type == expected_type:
                return body[1:]
            assert msg_type != DISCONNECT, "Unexpected FIBRE disconnect"
            if msg_type == PING:
                self.send(PONG, body[1:])
        raise AssertionError(f"No FIBRE message of type {expected_type}")

    def check_syn(self):
        assert_equal(self.receive(SYN), VERSION.to_bytes(8, "little"))

    def ping(self):
        nonce = b"fibre-v4"
        self.send(PING, nonce)
        assert_equal(self.receive(PONG), nonce)


class FibreProtocolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Use the test's assigned TCP port numbers for UDP as well. There are
        # deliberately no TCP peers: the relay check must use FIBRE.
        self.extra_args = [[f"-udpport={p2p_port(i)},0", "-debug=udpnet"] for i in range(self.num_nodes)]
        self.setup_nodes()

    @contextmanager
    def peer(self):
        node = self.nodes[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.connect(("127.0.0.1", p2p_port(0)))
            peer = FibrePeer(sock, timeout=10 * self.options.timeout_factor)
            node.addudpnode(peer.address, LOCAL_SECRET, REMOTE_SECRET, False, "onetry")
            try:
                peer.check_syn()
                yield peer
            finally:
                peer.send(DISCONNECT)
                self.wait_until(lambda: all(info["addr"] != peer.address for info in node.getudppeerinfo()))

    def test_protocol_identity(self):
        self.log.info("Advertise and accept the protocol version used by origin/archive")
        with self.peer() as peer:
            peer.send(SYN, VERSION.to_bytes(8, "little"))
            assert_equal(peer.receive(KEEPALIVE), b"")
            peer.send(KEEPALIVE)
            peer.ping()

    def test_relay(self):
        self.log.info("Relay blocks without the height prefix using only UDP")
        node0, node1 = self.nodes
        # Give both nodes a recent common tip and leave initial block download.
        address = node0.get_deterministic_priv_key().address
        tip = self.generatetoaddress(node0, 1, address, sync_fun=self.no_op)[0]
        assert_equal(node1.submitblock(node0.getblock(tip, 0)), None)
        for node in self.nodes:
            assert not node.getblockchaininfo()["initialblockdownload"]
            assert_equal(node.getpeerinfo(), [])

        node0.addudpnode(f"127.0.0.1:{p2p_port(1)}", LOCAL_SECRET, REMOTE_SECRET, True, "add")
        node1.addudpnode(f"127.0.0.1:{p2p_port(0)}", REMOTE_SECRET, LOCAL_SECRET, True, "onetry")

        def connected():
            return all(any(peer["lastrecv"] > 0 for peer in node.getudppeerinfo()) for node in self.nodes)

        self.wait_until(connected)
        tip = self.generatetoaddress(node0, 1, address, sync_fun=self.no_op)[0]
        self.wait_until(lambda: node1.getbestblockhash() == tip)

        self.log.info("Re-establish the FIBRE connection after a node restart")
        self.restart_node(1)
        node1.addudpnode(f"127.0.0.1:{p2p_port(0)}", REMOTE_SECRET, LOCAL_SECRET, True, "onetry")
        self.wait_until(connected)
        tip = self.generatetoaddress(node1, 1, address, sync_fun=self.no_op)[0]
        self.wait_until(lambda: node0.getbestblockhash() == tip)
        for node in self.nodes:
            assert_equal(node.getpeerinfo(), [])

    def run_test(self):
        self.test_protocol_identity()
        self.test_relay()


if __name__ == "__main__":
    FibreProtocolTest(__file__).main()
