#!/usr/bin/env python3
# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test debug logging."""

import os
import platform
import signal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch


class LoggingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def relative_log_path(self, name):
        return os.path.join(self.nodes[0].chain_path, name)

    @staticmethod
    def _rpc_log_marker(method):
        return b"ThreadRPCServer method=" + method.encode()

    @staticmethod
    def _read_log_bytes(log_path, offset=0):
        try:
            with open(log_path, "rb") as log_file:
                log_file.seek(offset)
                return log_file.read()
        except FileNotFoundError:
            return b""

    def _wait_for_log_marker(self, log_path, marker, offset=0):
        self.wait_until(lambda: marker in self._read_log_bytes(log_path, offset))

    def _stop_node_with_deadline(self):
        node = self.nodes[0]
        node.stop_node(wait_until_stopped=False)
        node.wait_until_stopped(timeout=30)

    def _start_node_with_fresh_default_log(self):
        node = self.nodes[0]
        assert not node.running
        if node.debug_log_path.exists():
            node.debug_log_path.unlink()
        self.start_node(0, ["-debug=rpc"])

    def _wait_for_sighup_reopen(self, log_path):
        node = self.nodes[0]
        trigger_marker = self._rpc_log_marker("uptime")

        def trigger_and_check():
            node.uptime()
            return trigger_marker in self._read_log_bytes(log_path)

        self.wait_until(trigger_and_check)

    def _test_async_logging_burst(self):
        node = self.nodes[0]
        self._start_node_with_fresh_default_log()
        uptime_marker = self._rpc_log_marker("uptime")
        final_marker = self._rpc_log_marker("getmemoryinfo")

        for _ in range(256):
            node.uptime()
        node.getmemoryinfo()
        node.flushdebuglog()

        log_bytes = self._read_log_bytes(node.debug_log_path)
        assert log_bytes.count(uptime_marker) == 256
        assert final_marker in log_bytes

        self._stop_node_with_deadline()

        log_bytes = self._read_log_bytes(node.debug_log_path)
        assert b"Shutdown done" in log_bytes

    def _test_single_sighup_rotation(self):
        node = self.nodes[0]
        default_log_path = node.debug_log_path
        rotated_log_path = default_log_path.with_name("debug.log.single-rotation")
        assert not node.running
        if rotated_log_path.exists():
            rotated_log_path.unlink()
        self._start_node_with_fresh_default_log()

        before_marker = self._rpc_log_marker("getrpcinfo")
        after_marker = self._rpc_log_marker("getmemoryinfo")
        node.getrpcinfo()
        self._wait_for_log_marker(default_log_path, before_marker)
        default_log_path.rename(rotated_log_path)
        rotated_boundary = rotated_log_path.stat().st_size
        node.process.send_signal(signal.SIGHUP)
        self._wait_for_sighup_reopen(default_log_path)
        node.getmemoryinfo()
        self._wait_for_log_marker(default_log_path, after_marker)
        self._stop_node_with_deadline()

        rotated_bytes = self._read_log_bytes(rotated_log_path)
        current_bytes = self._read_log_bytes(default_log_path)
        assert before_marker in rotated_bytes
        assert after_marker in current_bytes
        assert after_marker not in self._read_log_bytes(rotated_log_path, rotated_boundary)
        assert b"Shutdown done" in current_bytes

    def _test_double_sighup_rotation(self):
        node = self.nodes[0]
        default_log_path = node.debug_log_path
        rotated_log_path_1 = default_log_path.with_name("debug.log.double-rotation-1")
        rotated_log_path_2 = default_log_path.with_name("debug.log.double-rotation-2")
        assert not node.running
        for rotated_log_path in (rotated_log_path_1, rotated_log_path_2):
            if rotated_log_path.exists():
                rotated_log_path.unlink()
        self._start_node_with_fresh_default_log()

        before_marker = self._rpc_log_marker("getrpcinfo")
        middle_marker = self._rpc_log_marker("getmemoryinfo")
        after_marker = self._rpc_log_marker("getindexinfo")
        node.getrpcinfo()
        self._wait_for_log_marker(default_log_path, before_marker)
        default_log_path.rename(rotated_log_path_1)
        rotated_boundary_1 = rotated_log_path_1.stat().st_size
        node.process.send_signal(signal.SIGHUP)
        self._wait_for_sighup_reopen(default_log_path)
        node.getmemoryinfo()
        self._wait_for_log_marker(default_log_path, middle_marker)

        default_log_path.rename(rotated_log_path_2)
        rotated_boundary_2 = rotated_log_path_2.stat().st_size
        node.process.send_signal(signal.SIGHUP)
        self._wait_for_sighup_reopen(default_log_path)
        node.getindexinfo()
        self._wait_for_log_marker(default_log_path, after_marker)
        self._stop_node_with_deadline()

        rotated_bytes_1 = self._read_log_bytes(rotated_log_path_1)
        rotated_bytes_2 = self._read_log_bytes(rotated_log_path_2)
        current_bytes = self._read_log_bytes(default_log_path)
        rotated_suffix_1 = self._read_log_bytes(rotated_log_path_1, rotated_boundary_1)
        rotated_suffix_2 = self._read_log_bytes(rotated_log_path_2, rotated_boundary_2)
        assert before_marker in rotated_bytes_1
        assert middle_marker in rotated_bytes_2
        assert after_marker in current_bytes
        assert middle_marker not in rotated_suffix_1
        assert after_marker not in rotated_suffix_1
        assert after_marker not in rotated_suffix_2
        assert b"Shutdown done" in current_bytes

    def run_test(self):
        # test default log file name
        default_log_path = self.relative_log_path("debug.log")
        assert os.path.isfile(default_log_path)

        self._stop_node_with_deadline()
        self._test_async_logging_burst()
        if platform.system() != "Windows":
            self._test_single_sighup_rotation()
            self._test_double_sighup_rotation()

        # test alternative log file name in datadir
        self.restart_node(0, ["-debuglogfile=foo.log"])
        assert os.path.isfile(self.relative_log_path("foo.log"))

        # test alternative log file name outside datadir
        tempname = os.path.join(self.options.tmpdir, "foo.log")
        self.restart_node(0, [f"-debuglogfile={tempname}"])
        assert os.path.isfile(tempname)

        # check that invalid log (relative) will cause error
        invdir = self.relative_log_path("foo")
        invalidname = os.path.join("foo", "foo.log")
        self.stop_node(0)
        exp_stderr = r"Error: Could not open debug log file \S+$"
        self.nodes[0].assert_start_raises_init_error([f"-debuglogfile={invalidname}"], exp_stderr, match=ErrorMatch.FULL_REGEX)
        assert not os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (relative) works after path exists
        self.stop_node(0)
        os.mkdir(invdir)
        self.start_node(0, [f"-debuglogfile={invalidname}"])
        assert os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (absolute) will cause error
        self.stop_node(0)
        invdir = os.path.join(self.options.tmpdir, "foo")
        invalidname = os.path.join(invdir, "foo.log")
        self.nodes[0].assert_start_raises_init_error([f"-debuglogfile={invalidname}"], exp_stderr, match=ErrorMatch.FULL_REGEX)
        assert not os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (absolute) works after path exists
        self.stop_node(0)
        os.mkdir(invdir)
        self.start_node(0, [f"-debuglogfile={invalidname}"])
        assert os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that -nodebuglogfile disables logging
        self.stop_node(0)
        os.unlink(default_log_path)
        assert not os.path.isfile(default_log_path)
        self.start_node(0, ["-nodebuglogfile"])
        self.nodes[0].uptime()
        assert not os.path.isfile(default_log_path)
        self._stop_node_with_deadline()
        assert not os.path.isfile(default_log_path)

        # just sanity check no crash here
        self.start_node(0, [f"-debuglogfile={os.devnull}"])

        self.log.info("Test -debug and -debugexclude raise when invalid values are passed")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-debug=abc"],
            expected_msg="Error: Unsupported logging category -debug=abc.",
            match=ErrorMatch.FULL_REGEX,
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-debugexclude=abc"],
            expected_msg="Error: Unsupported logging category -debugexclude=abc.",
            match=ErrorMatch.FULL_REGEX,
        )

        self.log.info("Test -loglevel raises when invalid values are passed")
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-loglevel=abc"],
            expected_msg="Error: Unsupported global logging level -loglevel=abc. Valid values: info, debug, trace.",
            match=ErrorMatch.FULL_REGEX,
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-loglevel=net:abc"],
            expected_msg="Error: Unsupported category-specific logging level -loglevel=net:abc.",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-loglevel=net:info:abc"],
            expected_msg="Error: Unsupported category-specific logging level -loglevel=net:info:abc.",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Test that -nodebug,-debug=0,-debug=none clear previously specified debug options")
        disable_debug_options = [
            '-debug=0',
            '-debug=none',
            '-nodebug'
        ]

        for disable_debug_opt in disable_debug_options:
            # Every category before disable_debug_opt will be ignored, including the invalid 'abc'
            self.restart_node(0, ['-debug=http', '-debug=abc', disable_debug_opt, '-debug=rpc', '-debug=net'])
            logging = self.nodes[0].logging()
            assert not logging['http']
            assert 'abc' not in logging
            assert logging['rpc']
            assert logging['net']

if __name__ == '__main__':
    LoggingTest(__file__).main()
