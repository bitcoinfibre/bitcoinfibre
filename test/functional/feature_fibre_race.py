#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Observe accepted UDP/compact-block races with Core's privacy settings."""

from feature_fibre_transport import BLOCK_HEADER, FibreTransportTest, header_packet
from test_framework.messages import (
    BlockTransactions, HeaderAndShortIDs, msg_block, msg_blocktxn,
    msg_cmpctblock, msg_sendcmpct,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.util import assert_equal


class FibreRaceTest(FibreTransportTest):
    def set_test_params(self):
        super().set_test_params()

    def race_lines(self, block):
        node = self.nodes[0]
        node.flushdebuglog()
        return [line for line in node.debug_log_path.read_text(encoding="utf-8").splitlines()
                if f"block={block.hash_hex}" in line and " winner=" in line]

    def run_test(self):
        node = self.nodes[0]
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        for logips in (False, True):
            self.restart_node(0, extra_args=self.extra_args[0] + [f"-logips={int(logips)}"])
            tcp = node.add_p2p_connection(P2PInterface())
            tcp.send_and_ping(msg_sendcmpct(announce=False, version=2))
            warmup = self.block()
            tcp.send_and_ping(msg_block(warmup))
            self.wait_until(lambda: node.getbestblockhash() == warmup.hash_hex)
            assert node.getpeerinfo()[0]["bip152_hb_to"]

            with self.peer() as udp:
                self.log.info(f"FIBRE wins over a pending compact-block request, {logips=}")
                block = self.block()
                compact = HeaderAndShortIDs()
                compact.initialize_from_block(block, prefill_list=[], use_witness=True)
                tcp.send_and_ping(msg_cmpctblock(compact.to_p2p()))
                with p2p_lock:
                    assert_equal(tcp.last_message["getblocktxn"].block_txn_request.blockhash, block.hash_int)
                with node.assert_debug_log([f"block={block.hash_hex}", "winner=FIBRE/UDP"]):
                    udp.send(BLOCK_HEADER | 64, header_packet(block))
                    self.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
                response = msg_blocktxn()
                response.block_transactions = BlockTransactions(block.hash_int, block.vtx)
                tcp.send_and_ping(response)
                lines = self.race_lines(block)
                assert_equal(len(lines), 1)
                assert "udp=n/a" not in lines[0] and "cmpct=n/a" not in lines[0]
                assert_equal(udp.address in lines[0], logips)
                assert_equal("127.0.0.1:" in lines[0], logips)

                self.log.info("Compact-block connection is observed once; late UDP is harmless")
                block = self.block()
                compact.initialize_from_block(block, use_witness=True)
                with node.assert_debug_log([f"block={block.hash_hex}", "winner=BIP152/CMPCTBLOCK"]):
                    tcp.send_and_ping(msg_cmpctblock(compact.to_p2p()))
                udp.send(BLOCK_HEADER | 64, header_packet(block))
                udp.ping()
                lines = self.race_lines(block)
                assert_equal(len(lines), 1)
                assert_equal("127.0.0.1:" in lines[0], logips)

                self.log.info("Disabling BENCH suppresses winner log output")
                node.logging(exclude=["bench"])
                block = self.block()
                udp.send(BLOCK_HEADER | 64, header_packet(block))
                self.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
                assert_equal(self.race_lines(block), [])


if __name__ == "__main__":
    FibreRaceTest(__file__).main()
