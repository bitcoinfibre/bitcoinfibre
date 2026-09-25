#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Native UDP lifecycle, malformed datagrams and Core validation boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import socket
import threading
import time

from feature_fibre_protocol import DISCONNECT, FibrePeer, LOCAL_SECRET, REMOTE_SECRET
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CTxOut, HeaderAndShortIDs
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises, assert_raises_rpc_error, p2p_port


CHUNK_SIZE = 1152
BLOCK_HEADER = 3


def header_packet(block):
    compact = HeaderAndShortIDs()
    compact.initialize_from_block(block, nonce=block.hash_int & ((1 << 64) - 1), use_witness=True)
    # Coinbase-only: no short IDs and therefore no per-short-ID lengths.
    data = compact.to_p2p().serialize()
    assert len(data) <= CHUNK_SIZE
    return ((block.hash_int & ((1 << 64) - 1)).to_bytes(8, "little") +
            len(data).to_bytes(4, "little") + bytes(3) + data.ljust(CHUNK_SIZE, b"\0"))


class FibreTransportTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.extra_args = [[f"-udpport={p2p_port(0)},0", "-debug=bench"]]
        self.setup_nodes()

    @contextmanager
    def peer(self, trusted=False, *, family=socket.AF_INET, group=0):
        node = self.nodes[0]
        host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        local_secret = f"{LOCAL_SECRET}-{group}-{family}"
        remote_secret = f"{REMOTE_SECRET}-{group}-{family}"
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((host, 0))
            sock.connect((host, p2p_port(group)))
            peer = FibrePeer(sock, 10 * self.options.timeout_factor,
                             local_secret=local_secret, remote_secret=remote_secret)
            node.addudpnode(peer.address, local_secret, remote_secret, trusted, "onetry", group)
            peer.check_syn()
            peer.handshake()
            try:
                yield peer
            finally:
                if node.running:
                    node.disconnectudpnode(peer.address)

    def block(self, offset=1, bad_height=False):
        node = self.nodes[0]
        tip = node.getblockheader(node.getbestblockhash())
        coinbase = create_coinbase(tip["height"] + 1)
        if bad_height:
            # Valid script size, but an overlong number for telemetry's BIP34
            # decoder. It must reach consensus rejection without an exception.
            coinbase.vin[0].scriptSig = b"\x05\x01\x00\x00\x00\x01"
        block = create_block(int(tip["hash"], 16), coinbase, ntime=tip["time"] + offset)
        block.solve()
        return block

    def test_packets_and_validation(self):
        node = self.nodes[0]
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        self.log.info("Drop truncated, unauthenticated and oversized datagrams")
        with self.peer() as peer:
            for size in (0, 1, 16, 17, 1185, 4096):
                peer.sock.send(bytes(size))
            peer.ping()

        self.log.info("Reject authenticated zero-sized and oversized FEC objects")
        for size in (0, 4_000_001):
            with self.peer() as peer:
                peer.send(BLOCK_HEADER, bytes(8) + size.to_bytes(4, "little") + bytes(3 + CHUNK_SIZE))
                assert_equal(peer.receive(DISCONNECT), b"")

        self.log.info("Trusted and untrusted UDP paths retain consensus checks")
        for trusted in (False, True):
            with self.peer(trusted) as peer:
                invalid = self.block(offset=3 + int(trusted), bad_height=True)
                tip = node.getbestblockhash()
                with node.assert_debug_log([f"UDP: Failed to decode block {invalid.hash_hex}"]):
                    peer.send(BLOCK_HEADER | 64, header_packet(invalid))
                assert_equal(node.getbestblockhash(), tip)
                valid = self.block()
                peer.send(BLOCK_HEADER | 64, header_packet(valid))
                self.wait_until(lambda: node.getbestblockhash() == valid.hash_hex)
                peer.ping()

        self.log.info("Neither trust mode bypasses the minimum-work header gate")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-minimumchainwork=ff"])
        for trusted in (False, True):
            with self.peer(trusted) as peer:
                block = self.block(offset=10 + int(trusted))
                tip = node.getbestblockhash()
                with node.assert_debug_log([f"UDP: Failed to decode block {block.hash_hex}"]):
                    peer.send(BLOCK_HEADER | 64, header_packet(block))
                assert_equal(node.getbestblockhash(), tip)
                assert_raises_rpc_error(-5, "Block not found", node.getblockheader, block.hash_hex)
                peer.ping()
        self.restart_node(0)

    def test_shutdown_notification(self):
        node = self.nodes[0]
        for queued in (False, True):
            self.log.info("Notify IPv4/IPv6 peers in both groups on shutdown (queued block: %s)", queued)
            self.restart_node(0, extra_args=[f"-udpport={p2p_port(group)},{group},1" for group in range(2)])
            with ExitStack() as stack:
                peers = [stack.enter_context(self.peer(family=family, group=group))
                         for group in range(2) for family in (socket.AF_INET, socket.AF_INET6)]
                started = [threading.Event() for _ in peers]

                def receive_disconnect(peer, first_header):
                    headers = 0
                    deadline = time.monotonic() + peer.timeout
                    while time.monotonic() < deadline:
                        peer.sock.settimeout(max(0.001, deadline - time.monotonic()))
                        msg_type, payload = peer.receive_packet()
                        if msg_type == DISCONNECT:
                            assert_equal(payload, b"")
                            return headers
                        if msg_type == BLOCK_HEADER:
                            headers += 1
                            first_header.set()
                    raise AssertionError("No shutdown disconnect")

                with ThreadPoolExecutor(max_workers=len(peers)) as executor:
                    notifications = [executor.submit(receive_disconnect, peer, event)
                                     for peer, event in zip(peers, started)]
                    if queued:
                        # A large prefilled coinbase leaves about 14 seconds of
                        # header traffic per 1-Mbps group. Capture continuously
                        # so the control datagram cannot be lost to a full socket.
                        block = self.block()
                        block.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, bytes(900_000)])))
                        block.hashMerkleRoot = block.calc_merkle_root()
                        block.solve()
                        assert_equal(node.submitblock(block.serialize().hex()), None)
                        for event in started:
                            assert event.wait(10 * self.options.timeout_factor)

                    start = time.monotonic()
                    node.stop_node(wait_until_stopped=False)
                    node.wait_until_stopped(timeout=10)
                    elapsed = time.monotonic() - start
                    assert elapsed < 10 * self.options.timeout_factor
                    counts = [future.result() for future in notifications]
                    if queued:
                        # Notification must not require draining the header data,
                        # even before considering its additional FEC packets.
                        assert all(0 < count < 900_000 // CHUNK_SIZE for count in counts), counts
                    else:
                        assert_equal(counts, [0] * len(peers))
                    self.log.info("Shutdown took %.3fs; header packets before disconnect: %s", elapsed, counts)

                # The sender is joined before notification; no queued packet or
                # duplicate disconnect may follow it once the process has exited.
                for peer in peers:
                    peer.sock.setblocking(False)
                    assert_raises(BlockingIOError, peer.sock.recv, 2048)
        self.start_node(0)

    def test_shutdown_and_bind_cleanup(self):
        node = self.nodes[0]
        self.log.info("Bound shutdown with an idle reader and sender")
        start = time.monotonic()
        self.stop_node(0)
        assert time.monotonic() - start < 10 * self.options.timeout_factor
        self.start_node(0)

        self.log.info("Bound shutdown during authenticated receive load")
        with self.peer() as peer:
            stop = threading.Event()

            def flood():
                payload = bytes(8) + (4096).to_bytes(4, "little") + bytes(3 + CHUNK_SIZE)
                while not stop.is_set():
                    try:
                        peer.send(BLOCK_HEADER, payload)
                    except OSError:
                        break

            thread = threading.Thread(target=flood)
            thread.start()
            try:
                start = time.monotonic()
                self.stop_node(0)
                assert time.monotonic() - start < 10 * self.options.timeout_factor
            finally:
                stop.set()
                thread.join()

        self.log.info("Clean up the first group when a later UDP bind fails")
        error = "Error: Failed to initialize FIBRE UDP ports or workers. Check the UDP configuration and debug log."
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("0.0.0.0", p2p_port(1)))
            node.assert_start_raises_init_error(
                extra_args=self.extra_args[0] + [f"-udpport={p2p_port(1)},1"], expected_msg=error)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("0.0.0.0", p2p_port(0)))

        self.log.info("Reject zero bandwidth before starting a sender")
        node.assert_start_raises_init_error(extra_args=[f"-udpport={p2p_port(0)},0,0"], expected_msg=error)
        self.start_node(0)
        with self.peer() as peer:
            peer.ping()

    def run_test(self):
        self.test_packets_and_validation()
        self.test_shutdown_notification()
        self.test_shutdown_and_bind_cleanup()


if __name__ == "__main__":
    FibreTransportTest(__file__).main()
