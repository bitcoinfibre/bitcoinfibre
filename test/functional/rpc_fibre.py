#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test FIBRE RPC validation, connection management and startup log privacy."""

from contextlib import ExitStack, contextmanager
import socket

from feature_fibre_protocol import FibrePeer
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import append_config, assert_equal, assert_raises_rpc_error, p2p_port


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

    def peer_configuration(self):
        # Receive times and RTTs may change while established peers exchange packets.
        return {peer["addr"]: (peer["group"], peer["ultimatetrust"])
                for peer in self.nodes[1].getudppeerinfo()}

    @contextmanager
    def connected_peer(self, command="onetry", *, family=socket.AF_INET):
        node = self.nodes[1]
        host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((host, 0))
            sock.connect((host, p2p_port(1)))
            peer = FibrePeer(sock, 10 * self.options.timeout_factor,
                             local_secret="local", remote_secret="remote")
            assert_equal(node.addudpnode(peer.address, "local", "remote", False, command), None)
            try:
                peer.check_syn()
                peer.handshake()
                yield peer
            finally:
                if node.running and node.process.poll() is None:
                    node.disconnectudpnode(peer.address)

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

    def test_ip_connections(self):
        self.log.info("Complete IPv4 and IPv6 UDP handshakes with both add and onetry")
        original_peers = self.peer_configuration()
        for family in (socket.AF_INET, socket.AF_INET6):
            for command in ("add", "onetry"):
                with self.connected_peer(command, family=family) as peer:
                    assert_equal(self.peer_configuration(), {**original_peers, peer.address: (0, False)})
                assert_equal(self.peer_configuration(), original_peers)

    def test_unsupported_networks(self):
        self.log.info("Reject Tor and I2P addresses without changing the peer list")
        node = self.nodes[1]
        with self.connected_peer() as peer:
            original_peers = self.peer_configuration()
            # Lookup parses these fixtures from Core's unit tests locally.
            for address in (
                "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333",
                "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p:8333",
            ):
                for command in ("add", "onetry"):
                    assert_raises_rpc_error(
                        -32602, "UDP connections only support IPv4 and IPv6 addresses",
                        node.addudpnode, address, "local", "remote", False, command,
                    )
                    assert_equal(self.peer_configuration(), original_peers)
                    assert_equal(node.process.poll(), None)
                    peer.ping()

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

    def test_startup_log_redaction(self):
        node = self.nodes[1]
        original_config = node.bitcoinconf.read_text()
        try:
            for source in ("command-line", "config-file"):
                self.log.info("Redact FIBRE connection secrets from %s startup logging", source)
                settings, secrets, peers = [], [], []
                for option, trusted in (("addudpnode", False), ("addtrustedudpnode", True)):
                    local_secret = f"startup-{source}-{option}-local-dummy"
                    remote_secret = f"startup-{source}-{option}-remote-dummy"
                    secrets.extend((local_secret, remote_secret))
                    sock = self.peers.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    sock.bind(("127.0.0.1", 0))
                    sock.connect(("127.0.0.1", p2p_port(1)))
                    peer = FibrePeer(sock, 10 * self.options.timeout_factor,
                                     local_secret=local_secret, remote_secret=remote_secret)
                    settings.append(f"{option}={peer.address},{local_secret},{remote_secret}")
                    peers.append((peer, trusted))

                extra_args = self.extra_args[1] + ["-logips=0"]
                if source == "config-file":
                    append_config(node.datadir_path, settings)
                    prefix = "Config file arg: [regtest] "
                else:
                    extra_args.extend(f"-{setting}" for setting in settings)
                    prefix = "Command-line arg: "
                expected = [f"{prefix}{option}=****" for option in ("addudpnode", "addtrustedudpnode")]
                # Keep ordinary startup diagnostics, and flush negative checks
                # after authenticated handshakes establish that startup finished.
                expected.append(f'Command-line arg: udpport="{p2p_port(1)},0"')
                with node.assert_debug_log(expected, unexpected_msgs=secrets):
                    self.restart_node(1, extra_args=extra_args)
                    for peer, _ in peers:
                        peer.check_syn()
                        peer.handshake()
                    info = {entry["addr"]: entry for entry in node.getudppeerinfo()}
                    assert_equal(len(info), len(peers))
                    for peer, trusted in peers:
                        assert_equal(info[peer.address]["ultimatetrust"], trusted)
                        assert_equal(info[peer.address]["group"], 0)
        finally:
            node.bitcoinconf.write_text(original_config)

    def run_test(self):
        with ExitStack() as self.peers:
            self.test_groups()
            self.test_connection_modes()
            self.test_ip_connections()
            self.test_unsupported_networks()
            self.test_disconnect()
            self.test_startup_log_redaction()


if __name__ == "__main__":
    FibreRPCTest(__file__).main()
