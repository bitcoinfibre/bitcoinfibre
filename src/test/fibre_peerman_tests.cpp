// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <net_processing.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(fibre_peerman_tests)

BOOST_FIXTURE_TEST_CASE(known_parent_and_unknown_parent, RegTestingSetup)
{
    CBlockHeader header;
    {
        LOCK(cs_main);
        const auto* tip{m_node.chainman->ActiveChain().Tip()};
        header.hashPrevBlock = tip->GetBlockHash();
        header.nBits = tip->nBits;
    }
    // A claimed-work check is not proof-of-work or consensus validation.
    BOOST_CHECK(m_node.peerman->CheckFibreBlockWork(header));
    header.hashPrevBlock.SetNull();
    BOOST_CHECK(!m_node.peerman->CheckFibreBlockWork(header));
}

BOOST_FIXTURE_TEST_CASE(below_minimum_chain_work, TestingSetup)
{
    CBlockHeader header;
    {
        LOCK(cs_main);
        const auto* tip{m_node.chainman->ActiveChain().Tip()};
        header.hashPrevBlock = tip->GetBlockHash();
        header.nBits = tip->nBits;
    }
    // Mainnet's known genesis parent alone cannot bypass Core's minimum work.
    BOOST_CHECK(!m_node.peerman->CheckFibreBlockWork(header));
}

BOOST_AUTO_TEST_SUITE_END()
