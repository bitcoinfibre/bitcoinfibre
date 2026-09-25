// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace {

struct RelayNotifications final : node::KernelNotifications, CValidationInterface {
    using KernelNotifications::KernelNotifications;

    std::vector<std::string> events;

    void blockAccepted(const CBlock&, const CBlockIndex& index) override
    {
        AssertLockHeld(cs_main);
        BOOST_CHECK(!(index.nStatus & BLOCK_HAVE_DATA));
        events.emplace_back("fibre");
    }

    void NewPoWValidBlock(const CBlockIndex* index, const std::shared_ptr<const CBlock>&) override
    {
        AssertLockHeld(cs_main);
        BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_DATA));
        events.emplace_back("core");
    }

    void blockConnected(const CBlockIndex&) override
    {
        AssertLockHeld(cs_main);
        events.emplace_back("connected");
    }
};

struct RelayTestingSetup : ChainTestingSetup {
    // Keep the genesis tip recent enough to leave IBD before the test block.
    FakeNodeClock clock{std::chrono::seconds{Params().GenesisBlock().nTime + 100}};

    RelayTestingSetup() : ChainTestingSetup{ChainType::REGTEST}
    {
        // ChainTestingSetup has not loaded a chainstate or created PeerManager.
        // Replace its notification implementation before constructing users.
        m_node.chainman.reset();
        m_node.notifications = std::make_unique<RelayNotifications>(
            Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));
        m_make_chainman();
        LoadVerifyActivateChainstate();
        BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
        Notifications().events.clear();
        m_node.validation_signals->RegisterValidationInterface(&Notifications());
    }

    ~RelayTestingSetup()
    {
        m_node.validation_signals->UnregisterValidationInterface(&Notifications());
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    }

    RelayNotifications& Notifications()
    {
        return static_cast<RelayNotifications&>(*m_node.notifications);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(fibre_validation_tests, RelayTestingSetup)

BOOST_AUTO_TEST_CASE(relay_precedes_compact_announcement)
{
    const auto blocks{CreateBlockChain(1, Params())};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(blocks.front(), true, true, nullptr));

    // NewPoWValidBlock runs synchronously and can construct/announce compact
    // blocks. FIBRE must start first, regardless of how expensive that work is.
    // Check the execution order, not wall-clock timing or scheduler luck.
    const std::vector<std::string> expected{"fibre", "core", "connected"};
    BOOST_CHECK_EQUAL_COLLECTIONS(Notifications().events.begin(), Notifications().events.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(relay_eligibility_and_validation_unchanged)
{
    const auto blocks{CreateBlockChain(2, Params())};
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(blocks.front(), true, true, nullptr));
    Notifications().events.clear();

    // An equal-work competing block retains the original FIBRE relay trigger,
    // even though it does not extend the active tip required by Core's signal.
    auto competing{std::make_shared<CBlock>(*blocks.front())};
    ++competing->nTime;
    competing->nNonce = 0;
    while (!CheckProofOfWork(competing->GetHash(), competing->nBits, Params().GetConsensus())) ++competing->nNonce;
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(competing, true, true, nullptr));
    const std::vector<std::string> expected{"fibre"};
    BOOST_CHECK_EQUAL_COLLECTIONS(Notifications().events.begin(), Notifications().events.end(), expected.begin(), expected.end());

    // Moving the relay earlier must not put it before block validity checks.
    Notifications().events.clear();
    blocks.back()->hashMerkleRoot.SetNull();
    BOOST_CHECK(!m_node.chainman->ProcessNewBlock(blocks.back(), true, true, nullptr));
    BOOST_CHECK(Notifications().events.empty());
}

BOOST_AUTO_TEST_SUITE_END()
