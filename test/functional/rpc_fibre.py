#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test FIBRE RPC argument validation and connection management."""

from contextlib import ExitStack
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, p2p_port


class FibreRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Node 0 has no UDP ports. Node 1 has two bandwidth groups.
        self.extra_args = [
            ["-rpcdoccheck=1"],
            [f"-udpport={p2p_port(1)},0", f"-udpport={p2p_port(2)},1", "-rpcdoccheck=1"],
        ]
        self.setup_nodes()

    def peer_address(self):
        peer = self.peers.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        peer.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{peer.getsockname()[1]}"

    def test_groups(self):
        self.log.info("Reject invalid groups, including the default when no UDP port is bound")
        address = self.peer_address()
        for node, invalid_groups in (
            (self.nodes[0], ((), (None,), (0,), (1,), (-1,), (2**63 - 1,), (-2**63,))),
            (self.nodes[1], ((-1,), (2,), (3,), (2**63 - 1,), (-2**63,))),
        ):
            for command in ("add", "onetry"):
                for group in invalid_groups:
                    assert_raises_rpc_error(
                        -32602, "Group out of range or UDP port not bound",
                        node.addudpnode, address, "local", "remote", False, command, *group,
                    )
            assert_equal(node.getudppeerinfo(), [])

        self.log.info("Accept the first and last groups and default omitted or null groups to zero")
        node = self.nodes[1]
        for command in ("add", "onetry"):
            for group, expected in (((), 0), ((None,), 0), ((0,), 0), ((1,), 1)):
                address = self.peer_address()
                assert_equal(node.addudpnode(address, "local", "remote", False, command, *group), None)
                info = [peer for peer in node.getudppeerinfo() if peer["addr"] == address]
                assert_equal(len(info), 1)
                assert_equal(info[0]["group"], expected)

    def test_connection_modes(self):
        self.log.info("Reject unsupported network modes without changing the peer list")
        node = self.nodes[1]
        address = self.peer_address()
        original_peers = {peer["addr"] for peer in node.getudppeerinfo()}
        for command in ("add", "onetry"):
            for connection_type in (
                "inbound_only",
                "outbound_only",
                "I_certify_remote_is_listening_and_not_a_DoS_target_outbound_only",
                "I_certify_remote_is_listening_and_not_a_DoS_target_oubound_only",
                "unknown",
            ):
                assert_raises_rpc_error(
                    -32602, "Only bidirectional UDP connections are supported",
                    node.addudpnode, address, "local", "remote", False, command, 0, connection_type,
                )
        assert_equal({peer["addr"] for peer in node.getudppeerinfo()}, original_peers)

        self.log.info("Accept explicit bidirectional and null connection types")
        for command in ("add", "onetry"):
            for connection_type in ("bidirectional", None):
                address = self.peer_address()
                assert_equal(node.addudpnode(address, "local", "remote", False, command, None, connection_type), None)
                info = [peer for peer in node.getudppeerinfo() if peer["addr"] == address]
                assert_equal(len(info), 1)
                assert_equal(info[0]["group"], 0)

    def test_disconnect(self):
        self.log.info("Return null when disconnecting peers with RPC result checking enabled")
        node = self.nodes[1]
        for command in ("add", "onetry"):
            address = self.peer_address()
            node.addudpnode(address, "local", "remote", False, command)
            assert address in {peer["addr"] for peer in node.getudppeerinfo()}
            assert_equal(node.disconnectudpnode(address), None)
            assert address not in {peer["addr"] for peer in node.getudppeerinfo()}
            # Disconnecting an absent peer is also a successful null result.
            assert_equal(node.disconnectudpnode(address), None)
        assert_equal(self.nodes[0].disconnectudpnode(self.peer_address()), None)

    def run_test(self):
        with ExitStack() as self.peers:
            self.test_groups()
            self.test_connection_modes()
            self.test_disconnect()


if __name__ == "__main__":
    FibreRPCTest(__file__).main()
