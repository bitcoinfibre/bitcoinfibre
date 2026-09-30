#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Retire TCP block requests when their blocks arrive through FIBRE."""

from copy import deepcopy
import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    BlockTransactions,
    CBlockHeader,
    HeaderAndShortIDs,
    msg_block,
    msg_blocktxn,
    msg_cmpctblock,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


LOCAL_SECRET = "fibre-test-local"
REMOTE_SECRET = "fibre-test-remote"


class FibreDownloadsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Connect the nodes only over UDP. Synthetic TCP peers leave their block
        # requests unanswered until the test explicitly supplies a response.
        self.extra_args = [[f"-udpport={p2p_port(i)},0"] for i in range(self.num_nodes)]
        self.setup_nodes()

    def next_block(self):
        sender = self.nodes[0]
        tip = sender.getblockheader(sender.getbestblockhash())
        block = create_block(int(tip["hash"], 16), create_coinbase(tip["height"] + 1), ntime=tip["time"] + 1)
        block.solve()
        return block

    def wait_for_inflight(self, expected):
        self.wait_until(lambda: [peer["inflight"] for peer in self.nodes[1].getpeerinfo()] == expected, timeout=10)

    def run_test(self):
        sender, receiver = self.nodes
        tip = self.generatetoaddress(sender, 1, sender.get_deterministic_priv_key().address, sync_fun=self.no_op)[0]
        assert_equal(receiver.submitblock(sender.getblock(tip, 0)), None)
        assert all(not node.getblockchaininfo()["initialblockdownload"] for node in self.nodes)
        peer = receiver.add_p2p_connection(P2PInterface())

        self.log.info("Clear an out-of-order FIBRE download while retaining its missing parent")
        parent = self.next_block()
        assert_equal(sender.submitblock(parent.serialize().hex()), None)
        child = self.next_block()
        peer.send_and_ping(msg_headers([CBlockHeader(parent), CBlockHeader(child)]))
        peer.wait_for_getdata([parent.hash_int, child.hash_int])
        self.wait_for_inflight([[2, 3]])

        # Establish UDP after the sender accepts the parent so only the child
        # reaches the receiver through FIBRE. Its parent is still header-only.
        sender.addudpnode(f"127.0.0.1:{p2p_port(1)}", LOCAL_SECRET, REMOTE_SECRET, True, "add")
        receiver.addudpnode(f"127.0.0.1:{p2p_port(0)}", REMOTE_SECRET, LOCAL_SECRET, True, "onetry")
        self.wait_until(lambda: all(any(info["lastrecv"] > 0 for info in node.getudppeerinfo()) for node in self.nodes))
        assert_equal(sender.submitblock(child.serialize().hex()), None)
        self.wait_until(lambda: receiver.getblockheader(child.hash_hex)["nTx"] == 1)
        assert_equal(receiver.getblock(child.hash_hex, 0), child.serialize().hex())
        assert_equal(receiver.getbestblockhash(), tip)
        self.wait_for_inflight([[2]])
        peer.send_and_ping(msg_block(parent))
        self.wait_until(lambda: receiver.getbestblockhash() == child.hash_hex)
        self.wait_for_inflight([[]])

        self.log.info("Rejected block data must not cancel a pending download")
        block = self.next_block()
        peer.send_and_ping(msg_headers([CBlockHeader(block)]))
        peer.wait_for_getdata([block.hash_int])
        self.wait_for_inflight([[4]])
        mutated = deepcopy(block)
        mutated.vtx[0].vout[0].nValue += 1  # Preserve the header, but break its Merkle root.
        assert_equal(receiver.submitblock(mutated.serialize().hex()), "bad-txnmrklroot")
        peer.sync_with_ping()
        self.wait_for_inflight([[4]])
        assert_equal(sender.submitblock(block.serialize().hex()), None)
        self.wait_until(lambda: receiver.getbestblockhash() == block.hash_hex)
        self.wait_for_inflight([[]])

        self.log.info("Clear parallel compact-block requests from every peer")
        peers = [peer, receiver.add_p2p_connection(P2PInterface())]
        # Deliver a block from each peer so both become high-bandwidth compact
        # block peers and can have parallel requests for the following block.
        for tcp_peer in peers:
            tcp_peer.send_and_ping(msg_sendcmpct(announce=False, version=2))
            warmup = self.next_block()
            tcp_peer.send_and_ping(msg_block(warmup))
            self.wait_until(lambda: sender.getbestblockhash() == warmup.hash_hex)
        assert all(info["bip152_hb_to"] for info in receiver.getpeerinfo())

        block = self.next_block()
        compact = HeaderAndShortIDs()
        # Omit the coinbase so each peer leaves a getblocktxn request pending.
        compact.initialize_from_block(block, prefill_list=[], use_witness=True)
        for tcp_peer in peers:
            tcp_peer.send_and_ping(msg_cmpctblock(compact.to_p2p()))
            with p2p_lock:
                request = tcp_peer.last_message["getblocktxn"].block_txn_request
                assert_equal(request.blockhash, block.hash_int)
                assert_equal(request.to_absolute(), [0])
        self.wait_for_inflight([[7], [7]])
        assert_equal(sender.submitblock(block.serialize().hex()), None)
        self.wait_until(lambda: receiver.getbestblockhash() == block.hash_hex)
        self.wait_for_inflight([[], []])
        # A late TCP response must be harmless after FIBRE completed the block.
        response = msg_blocktxn()
        response.block_transactions = BlockTransactions(block.hash_int, block.vtx)
        peer.send_and_ping(response)

        self.log.info("Completed downloads must not cause a later peer timeout")
        now = int(time.time())
        receiver.setmocktime(now + 601)
        for tcp_peer in peers:
            tcp_peer.sync_with_ping()
        self.wait_for_inflight([[], []])

        self.log.info("A genuinely unanswered download must still time out")
        missing = self.next_block()
        peer.send_and_ping(msg_headers([CBlockHeader(missing)]))
        peer.wait_for_getdata([missing.hash_int])
        self.wait_for_inflight([[8], []])
        with receiver.assert_debug_log([f"Timeout downloading block {missing.hash_hex}"]):
            receiver.setmocktime(now + 1202)
            peer.wait_for_disconnect()
        peers[1].sync_with_ping()
        self.wait_for_inflight([[]])


if __name__ == "__main__":
    FibreDownloadsTest(__file__).main()
