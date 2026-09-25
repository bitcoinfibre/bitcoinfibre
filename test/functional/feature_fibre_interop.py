#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exchange blocks with the corrected, pinned FIBRE 31 implementation.

Supply --fibre-reference-bindir for a build of source commit
65cbe2434b2e06cebaf778216ed82010a0839e87. Protocol version 4 alone does not
identify this format: older modern FIBRE builds used a height prefix.
"""

import time

from feature_fibre_protocol import FibreProtocolTest, LOCAL_SECRET, REMOTE_SECRET
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet import MiniWallet


class FibreInteropTest(FibreProtocolTest):
    def set_test_params(self):
        super().set_test_params()

    def add_options(self, parser):
        parser.add_argument("--fibre-reference-bindir", help="Directory containing corrected FIBRE 31 binaries")

    def skip_test_if_missing_module(self):
        if not self.options.fibre_reference_bindir:
            raise SkipTest("Supply --fibre-reference-bindir for corrected FIBRE 31 interoperability")

    def setup_network(self):
        self.extra_init = [{}, {"binaries": self.get_binaries(self.options.fibre_reference_bindir), "version": 310000}]
        # Pace a real multi-chunk exchange on loaded CI hosts. The reference
        # still has libevent; its per-event debug log is unrelated to wire bytes.
        self.extra_args = [[f"-udpport={p2p_port(i)},0,64"] for i in range(2)]
        self.extra_args[1].append("-debugexclude=libevent")
        self.setup_nodes()

    def run_test(self):
        current, reference = self.nodes
        assert_equal(reference.getnetworkinfo()["version"], 310000)
        wallet = MiniWallet(current)
        common = self.generatetoaddress(current, 101, wallet.get_address(), sync_fun=self.no_op)
        for block in common:
            assert_equal(reference.submitblock(current.getblock(block, 0)), None)
        wallet.rescan_utxos()
        for trusted in (False, True):
            if trusted:
                # Clear pending repeated disconnects before reusing addresses.
                self.restart_node(0)
                self.restart_node(1)
            for index, node in enumerate(self.nodes):
                node.addudpnode(f"127.0.0.1:{p2p_port(1-index)}",
                                LOCAL_SECRET if index == 0 else REMOTE_SECRET,
                                REMOTE_SECRET if index == 0 else LOCAL_SECRET,
                                trusted, "onetry")
            self.wait_until(lambda: all(any(p["lastrecv"] > 0 for p in n.getudppeerinfo()) for n in self.nodes))
            for index in (0, 1):
                sender, receiver = self.nodes[index], self.nodes[1-index]
                for outputs in (1, 100, 1000):
                    tx = wallet.send_self_transfer_multi(from_node=sender, num_outputs=outputs, confirmed_only=True)
                    assert tx["txid"] not in receiver.getrawmempool()
                    start = time.monotonic()
                    tip = self.generatetoaddress(sender, 1, wallet.get_address(), sync_fun=self.no_op)[0]
                    self.wait_until(lambda: receiver.getbestblockhash() == tip)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    self.log.info(f"UDP block {index}->{1-index}, {trusted=}, {outputs=}, submit-to-poll={elapsed_ms:.1f} ms")
                    assert_equal(receiver.getblock(tip, 0), sender.getblock(tip, 0))
                    assert_equal(receiver.getblock(tip)["nTx"], 2)
                    wallet.rescan_utxos()
            for index, node in enumerate(self.nodes):
                assert_equal(node.getpeerinfo(), [])
                node.disconnectudpnode(f"127.0.0.1:{p2p_port(1-index)}")


if __name__ == "__main__":
    FibreInteropTest(__file__).main()
