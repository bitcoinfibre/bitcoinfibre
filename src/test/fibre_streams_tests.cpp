// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <fibre/streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(fibre_streams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(boundaries_and_truncation)
{
    std::vector<unsigned char> bytes;
    VectorOutputStream output{&bytes};
    output.write({});
    VectorInputStream input{&bytes};
    input.seek(0);
    input.read({});
    std::array<std::byte, 1> byte{};
    BOOST_CHECK_THROW(input.read(byte), std::ios_base::failure);
    BOOST_CHECK_THROW(input.seek(1), std::ios_base::failure);
    output << uint32_t{0x04030201};
    BOOST_CHECK(bytes == std::vector<unsigned char>({1, 2, 3, 4}));
    uint32_t value{0};
    input >> value;
    BOOST_CHECK_EQUAL(value, 0x04030201U);
    input.read({});
    BOOST_CHECK_THROW(input.read(byte), std::ios_base::failure);
    input.seek(3);
    BOOST_CHECK_THROW(input >> value, std::ios_base::failure);
    BOOST_CHECK_EQUAL(input.pos(), 3U);
    BOOST_CHECK_THROW(output.skip_bytes(std::numeric_limits<size_t>::max()), std::ios_base::failure);
    BOOST_CHECK_EQUAL(bytes.size(), 4U);
}

BOOST_AUTO_TEST_CASE(overwrite_and_padding)
{
    std::vector<unsigned char> bytes{1, 2, 3};
    VectorOutputStream output{&bytes, 1};
    output << uint8_t{4};
    output.skip_bytes(3);
    output << uint8_t{5};
    BOOST_CHECK(bytes == std::vector<unsigned char>({1, 4, 3, 0, 0, 5}));
    BOOST_CHECK_EQUAL(output.pos(), 6U);
}

BOOST_AUTO_TEST_SUITE_END()
