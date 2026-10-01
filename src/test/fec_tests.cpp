// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <fec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

BOOST_FIXTURE_TEST_SUITE(fec_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(completed_single_chunk_move)
{
    for (const size_t bytes : {1, FEC_CHUNK_SIZE - 1, FEC_CHUNK_SIZE}) {
        BOOST_TEST_CONTEXT("bytes=" << bytes) {
            std::array<unsigned char, FEC_CHUNK_SIZE> expected{};
            for (size_t i = 0; i < bytes; ++i) expected[i] = static_cast<unsigned char>(i);
            std::array<unsigned char, FEC_CHUNK_SIZE> previous;
            previous.fill(0xff);

            // Overwrite a completed destination so failing to copy the payload
            // returns known, different bytes instead of uninitialized memory.
            FECDecoder decoder{bytes};
            BOOST_REQUIRE(decoder.ProvideChunk(previous.data(), 0));
            BOOST_REQUIRE(decoder.DecodeReady());
            {
                FECDecoder source{bytes};
                BOOST_REQUIRE(source.ProvideChunk(expected.data(), 0));
                BOOST_REQUIRE(source.DecodeReady());
                decoder = std::move(source);
            }
            BOOST_REQUIRE(decoder.DecodeReady());
            const auto* recovered{static_cast<const unsigned char*>(decoder.GetDataPtr(0))};
            BOOST_CHECK(std::equal(expected.begin(), expected.begin() + bytes, recovered));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
