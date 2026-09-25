#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""FIBRE's optional address gate preserves Core's default announcements."""

import time

from test_framework.messages import CBlockHeader, from_hex, msg_headers
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


EXTERNAL_IP = "42.42.42.42"


class AddrReceiver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.announcements = 0

    def on_addr(self, message):
        self.announcements += sum(addr.ip == EXTERNAL_IP for addr in message.addrs)

    def on_addrv2(self, message):
        self.on_addr(message)


class FibreAdvertiseLocalTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.bind_to_localhost_only = False
        self.extra_args = [["-bind=127.0.0.1", f"-externalip={EXTERNAL_IP}"]]

    def run_test(self):
        node = self.nodes[0]
        cases = [
            ([], True),
            (["-advertiselocal=1"], True),
            (["-advertiselocal=0"], False),
            (["-advertiselocal=0", "-discover=0"], False),
            (["-advertiselocal=1", "-discover=0"], True),
            (["-advertiselocal=1", "-listen=0"], False),
        ]
        for options, expected in cases:
            self.log.info(f"Check initial and periodic announcements with {options=}")
            args = [f"-externalip={EXTERNAL_IP}"] + options
            if "-listen=0" not in options:
                args.append("-bind=127.0.0.1")
            self.restart_node(0, extra_args=args)
            assert not node.getblockchaininfo()["initialblockdownload"]
            node.setmocktime(int(time.time()))
            peer = node.add_outbound_p2p_connection(AddrReceiver(), p2p_idx=0, connection_type="outbound-full-relay")
            peer.sync_with_ping()
            with p2p_lock:
                assert_equal(peer.announcements, int(expected))
            # Protect the outbound connection from stale-tip eviction.
            tip = from_hex(CBlockHeader(), node.getblockheader(node.getbestblockhash(), False))
            peer.send_and_ping(msg_headers([tip]))
            # Same generous exponential-timer bound as Core's self-announcement test.
            node.bumpmocktime(20 * 24 * 60 * 60)
            peer.sync_with_ping()
            with p2p_lock:
                assert_equal(peer.announcements, 2 * int(expected))


if __name__ == "__main__":
    FibreAdvertiseLocalTest(__file__).main()
