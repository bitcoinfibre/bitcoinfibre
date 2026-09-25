#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Retain early body chunks without forwarding them again during local replay."""

import selectors
import socket
import threading
import time

from feature_fibre_protocol import DISCONNECT, FibrePeer, LOCAL_SECRET, PING, PONG, REMOTE_SECRET
from test_framework.crypto.poly1305 import Poly1305
from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet import MiniWallet


def message_body(packet):
    return bytes(value ^ packet[i % 8] for i, value in enumerate(packet[16:]))


class ReorderingProxy:
    """Hold all but the first header chunk until the entire body is received.

    An authenticated ping after the body establishes that the receiver processed
    those packets before the remaining header is released. No scheduler delay or
    artificial production-code hook is needed to exercise the handoff.
    """

    def __init__(self, body_packet_limit=None):
        self.stop = threading.Event()
        self.body_drained = threading.Event()
        self.release_header = threading.Event()
        self.release_body = threading.Event()
        self.errors = []
        self.header_packets = []
        self.first_header_sent = False
        self.body_packets = 0
        self.body_packet_limit = body_packet_limit
        self.first_body_packet = None
        self.held_body_packets = []
        self.marker = b"bodydone"
        self.sockets = []
        self.selector = selectors.DefaultSelector()
        for i in range(2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.bind(("127.0.0.1", p2p_port(i + 2)))
            sock.setblocking(False)
            self.sockets.append(sock)
            self.selector.register(sock, selectors.EVENT_READ, i)
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def forward(self, direction, packet):
        self.sockets[1 - direction].sendto(packet, ("127.0.0.1", p2p_port(1 - direction)))

    def ping_receiver(self):
        self.body_drained.clear()
        ping = bytes([PING]) + self.marker
        tag = Poly1305(hash256(REMOTE_SECRET.encode())[:8] * 4).tag(ping)
        self.forward(0, tag + bytes(value ^ tag[i % 8] for i, value in enumerate(ping)))

    def run(self):
        try:
            while not self.stop.is_set():
                if self.release_header.is_set() and self.header_packets:
                    for packet in self.header_packets:
                        self.forward(0, packet)
                    self.header_packets.clear()
                if self.release_body.is_set() and self.held_body_packets:
                    for packet in self.held_body_packets:
                        self.forward(0, packet)
                    self.held_body_packets.clear()
                for key, _ in self.selector.select(0.01):
                    packet, _ = key.fileobj.recvfrom(2048)
                    body = message_body(packet)
                    msg_type = body[0] & 63
                    if key.data == 0 and msg_type == 3 and not self.release_header.is_set():
                        if not self.first_header_sent:
                            # At least two data chunks are required, so the
                            # receiver cannot finish the header from this one.
                            assert int.from_bytes(body[9:13], "little") > 1152
                            assert_equal(int.from_bytes(body[13:16], "little"), 0)
                            self.first_header_sent = True
                            self.forward(0, packet)
                        else:
                            self.header_packets.append(packet)
                        continue
                    if key.data == 0 and msg_type == 4:
                        self.body_packets += 1
                        if self.first_body_packet is None:
                            self.first_body_packet = packet
                        chunks = (int.from_bytes(body[9:13], "little") + 1151) // 1152
                        # Sender emits raw data, k+10 parity chunks, and an
                        # initial three-data-chunk burst. All fit the bounded
                        # pending-body queue in this fixture.
                        total = 2 * chunks + 10 + min(3, chunks)
                        assert total < 256
                        if self.body_packet_limit is None or self.body_packets <= self.body_packet_limit:
                            self.forward(0, packet)
                        else:
                            self.held_body_packets.append(packet)
                        if self.body_packets == total:
                            self.ping_receiver()
                        continue
                    if key.data == 1 and msg_type == 6 and body[1:] == self.marker:
                        self.body_drained.set()
                        continue
                    self.forward(key.data, packet)
        except Exception as error:
            self.errors.append(error)
            self.body_drained.set()

    def close(self):
        self.stop.set()
        self.thread.join()
        self.selector.close()
        for sock in self.sockets:
            sock.close()
        if self.errors:
            raise self.errors[0]


class FibreBurstTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.extra_args = [[f"-udpport={p2p_port(i)},0,1024"] for i in range(2)]
        self.setup_nodes()

    def forwarded_body_packets(self, peer):
        """Capture body packets through two successive sender-queue barriers.

        PONG uses the low-priority queue. A second request sent after receiving
        the first response forces another queue selection, also covering a
        high-priority replay copy queued while the sender selected low priority.
        Call only after the receiver has processed the relevant input/worker job.
        """
        packets = []
        for marker in (b"drainone", b"draintwo"):
            peer.send(PING, marker)
            deadline = time.monotonic() + peer.timeout
            while True:
                peer.sock.settimeout(max(0.001, deadline - time.monotonic()))
                packet = peer.sock.recv(2048)
                body = message_body(packet)
                assert_equal(Poly1305(peer.recv_key).tag(body), packet[:16])
                msg_type = body[0] & 63
                assert msg_type != DISCONNECT
                if msg_type == PONG and body[1:] == marker:
                    break
                if msg_type == PING:
                    peer.send(PONG, body[1:])
                if msg_type == 4:
                    packets.append(body[1:])
                assert time.monotonic() < deadline
        return packets

    def test_forward_once(self, wallet):
        self.log.info("Forward a trusted early body packet once, retaining it for local replay")
        self.restart_node(0)
        self.restart_node(1)
        sender, receiver = self.nodes
        proxy = ReorderingProxy(body_packet_limit=1)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.bind(("127.0.0.1", 0))
                sock.connect(("127.0.0.1", p2p_port(1)))
                downstream = FibrePeer(sock, timeout=10 * self.options.timeout_factor)
                receiver.addudpnode(downstream.address, LOCAL_SECRET, REMOTE_SECRET, True, "onetry")
                downstream.check_syn()
                downstream.handshake()
                for i, node in enumerate(self.nodes):
                    node.addudpnode(f"127.0.0.1:{p2p_port(i + 2)}",
                                    LOCAL_SECRET if i == 0 else REMOTE_SECRET,
                                    REMOTE_SECRET if i == 0 else LOCAL_SECRET, True, "onetry")
                self.wait_until(lambda: all(any(p["max_recent_rtt"] > 0 for p in n.getudppeerinfo()) for n in self.nodes))
                chain = wallet.create_self_transfer_chain(chain_length=200)
                original_tip = receiver.getbestblockhash()
                tip = self.generateblock(sender, wallet.get_address(), [tx["hex"] for tx in chain], sync_fun=self.no_op)["hash"]
                self.wait_until(proxy.body_drained.is_set, timeout=15)
                if proxy.errors:
                    raise proxy.errors[0]

                first = proxy.first_body_packet
                first_body = message_body(first)
                # One chunk cannot complete this block, even after its header
                # arrives. Completed-block relay must not affect packet counts.
                assert int.from_bytes(first_body[9:13], "little") > 2 * 1152
                assert_equal(int.from_bytes(first_body[13:16], "little"), 0)
                assert_equal(receiver.getrawmempool(), [])
                forwarded = self.forwarded_body_packets(downstream)
                assert_equal(len(forwarded), 1)
                assert_equal(forwarded[0], first_body[1:])
                assert_equal(receiver.getbestblockhash(), original_tip)

                # This positive log follows local replay and the worker's
                # subsequent mempool fill. Merely waiting for header completion
                # would not establish that replay had finished.
                with receiver.assert_debug_log([f"UDP: Initialized block {tip} with"], timeout=10):
                    proxy.release_header.set()
                assert_equal(len(self.forwarded_body_packets(downstream)), 0)
                assert_equal(receiver.getbestblockhash(), original_tip)

                # Replay must have fed the decoder: retransmission is already
                # known, while a fresh network chunk still forwards normally.
                proxy.forward(0, first)
                # A ping through the source proxy serializes packet handling
                # before the downstream barriers.
                proxy.ping_receiver()
                self.wait_until(proxy.body_drained.is_set)
                assert_equal(len(self.forwarded_body_packets(downstream)), 0)
                fresh = next(packet for packet in proxy.held_body_packets
                             if int.from_bytes(message_body(packet)[13:16], "little") == 1)
                fresh_body = message_body(fresh)
                proxy.forward(0, fresh)
                proxy.ping_receiver()
                self.wait_until(proxy.body_drained.is_set)
                forwarded = self.forwarded_body_packets(downstream)
                assert_equal(len(forwarded), 1)
                assert_equal(forwarded[0], fresh_body[1:])
                assert_equal(receiver.getbestblockhash(), original_tip)

                proxy.release_body.set()
                self.wait_until(lambda: receiver.getbestblockhash() == tip)
                assert_equal(receiver.getblock(tip, 0), sender.getblock(tip, 0))
                assert_equal(receiver.getrawmempool(), [])
        finally:
            proxy.close()

    def run_test(self):
        sender, receiver = self.nodes
        wallet = MiniWallet(sender)
        common = self.generatetoaddress(sender, 102, wallet.get_address(), sync_fun=self.no_op)
        for block in common:
            assert_equal(receiver.submitblock(sender.getblock(block, 0)), None)
        wallet.rescan_utxos()
        for trusted in (False, True):
            if trusted:
                self.restart_node(0)
                self.restart_node(1)
            proxy = ReorderingProxy()
            try:
                for i, node in enumerate(self.nodes):
                    node.addudpnode(f"127.0.0.1:{p2p_port(i + 2)}",
                                    LOCAL_SECRET if i == 0 else REMOTE_SECRET,
                                    REMOTE_SECRET if i == 0 else LOCAL_SECRET, trusted, "onetry")
                self.wait_until(lambda: all(any(p["max_recent_rtt"] > 0 for p in n.getudppeerinfo()) for n in self.nodes))
                chain = wallet.create_self_transfer_chain(chain_length=200)
                original_tip = receiver.getbestblockhash()
                tip = self.generateblock(sender, wallet.get_address(), [tx["hex"] for tx in chain], sync_fun=self.no_op)["hash"]
                self.wait_until(proxy.body_drained.is_set, timeout=15)
                if proxy.errors:
                    raise proxy.errors[0]
                assert proxy.header_packets
                assert_equal(receiver.getbestblockhash(), original_tip)
                proxy.release_header.set()
                self.wait_until(lambda: receiver.getbestblockhash() == tip)
                assert_equal(receiver.getblock(tip, 0), sender.getblock(tip, 0))
                assert_equal(receiver.getblock(tip)["nTx"], 201)
                assert_equal(receiver.getrawmempool(), [])
                for node in self.nodes:
                    assert_equal(node.getpeerinfo(), [])
            finally:
                proxy.close()

        self.test_forward_once(wallet)


if __name__ == "__main__":
    FibreBurstTest(__file__).main()
