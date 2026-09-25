#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test FIBRE header-chunk tracing independently of BENCH logging."""

import socket
import time

# Test will be skipped if we don't have bcc installed.
try:
    from bcc import BPF, USDT  # type: ignore[import]
except ImportError:
    pass

from feature_fibre_protocol import DISCONNECT, FibrePeer, LOCAL_SECRET, REMOTE_SECRET
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, bpf_cflags, p2p_port


BLOCK_HEADER = 3
CHUNK_SIZE = 1152

HEADER_CHUNK_PROGRAM = """
#include <uapi/linux/ptrace.h>

struct header_chunk {
    u64 hash_prefix;
    s64 queue_us;
    s64 maps_us;
    s64 chunks_us;
    s64 finish_us;
};

BPF_PERF_OUTPUT(header_chunks);
int trace_header_chunk(struct pt_regs *ctx) {
    struct header_chunk event = {};
    bpf_usdt_readarg(1, ctx, &event.hash_prefix);
    bpf_usdt_readarg(2, ctx, &event.queue_us);
    bpf_usdt_readarg(3, ctx, &event.maps_us);
    bpf_usdt_readarg(4, ctx, &event.chunks_us);
    bpf_usdt_readarg(5, ctx, &event.finish_us);
    header_chunks.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


class FibreTracepointTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.extra_args = [[f"-udpport={p2p_port(0)},0", "-debugexclude=bench"]]
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_linux()
        self.skip_if_no_bitcoind_tracepoints()
        self.skip_if_no_python_bcc()
        self.skip_if_no_bpf_permissions()
        self.skip_if_running_under_valgrind()

    def run_test(self):
        node = self.nodes[0]
        events = []
        ctx = USDT(pid=node.process.pid)
        ctx.enable_probe(probe="udp:block_header_chunk", fn_name="trace_header_chunk")
        bpf = BPF(text=HEADER_CHUNK_PROGRAM, usdt_contexts=[ctx], debug=0, cflags=bpf_cflags())

        def handle_chunk(_, data, __):
            event = bpf["header_chunks"].event(data)
            events.append((event.hash_prefix, (event.queue_us, event.maps_us, event.chunks_us, event.finish_us)))

        bpf["header_chunks"].open_perf_buffer(handle_chunk)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                sock.connect(("127.0.0.1", p2p_port(0)))
                peer = FibrePeer(sock, timeout=10 * self.options.timeout_factor)
                node.addudpnode(peer.address, LOCAL_SECRET, REMOTE_SECRET, False, "onetry")
                peer.check_syn()
                peer.handshake()
                try:
                    for bench_enabled in (False, True):
                        self.log.info(f"Trace the first header chunk with BENCH logging {bench_enabled=}")
                        node.logging(include=["bench"] if bench_enabled else [], exclude=[] if bench_enabled else ["bench"])
                        assert_equal(node.logging()["bench"], bench_enabled)
                        hash_prefix = 0x0102030405060708 + int(bench_enabled)
                        # Send just one of two chunks. This exercises header reception
                        # without submitting an incomplete header for reconstruction.
                        payload = hash_prefix.to_bytes(8, "little") + (2 * CHUNK_SIZE).to_bytes(4, "little")
                        payload += (0).to_bytes(3, "little") + bytes(CHUNK_SIZE)
                        events.clear()
                        start = time.monotonic()
                        peer.send(BLOCK_HEADER, payload)
                        peer.ping()

                        def received_event():
                            bpf.perf_buffer_poll(timeout=50)
                            return bool(events)

                        self.wait_until(received_event)
                        elapsed_us = (time.monotonic() - start) * 1_000_000
                        assert_equal(len(events), 1)
                        assert_equal(events[0][0], hash_prefix)
                        durations = events[0][1]
                        assert all(duration >= 0 for duration in durations)
                        assert sum(durations) <= elapsed_us

                        # A duplicate chunk must not produce a second first-chunk event.
                        peer.send(BLOCK_HEADER, payload)
                        peer.ping()
                        bpf.perf_buffer_poll(timeout=100)
                        assert_equal(len(events), 1)
                finally:
                    peer.send(DISCONNECT)
        finally:
            bpf.cleanup()


if __name__ == "__main__":
    FibreTracepointTest(__file__).main()
