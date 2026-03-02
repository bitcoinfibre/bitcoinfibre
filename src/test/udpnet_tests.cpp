// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <hash.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <udpapi.h>
#include <udpnet.h>
#include <util/fs_helpers.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(udpnet_tests, BasicTestingSetup)

// If the field order or types in SERIALIZE_METHODS are wrong, values come back corrupted.
BOOST_AUTO_TEST_CASE(udp_peer_entry_serialization)
{
    UDPPeerEntry orig;
    orig.addr_str        = "1.2.3.4:8444";
    orig.local_magic     = 0xdeadbeefcafe0001ULL;
    orig.remote_magic    = 0xcafebabe12345678ULL;
    orig.group           = 3;
    orig.fTrusted        = true;
    orig.connection_type = static_cast<uint8_t>(UDP_CONNECTION_TYPE_OUTBOUND_ONLY);

    DataStream ss{};
    ss << orig;

    UDPPeerEntry loaded;
    ss >> loaded;

    BOOST_CHECK_EQUAL(loaded.addr_str,        orig.addr_str);
    BOOST_CHECK_EQUAL(loaded.local_magic,     orig.local_magic);
    BOOST_CHECK_EQUAL(loaded.remote_magic,    orig.remote_magic);
    BOOST_CHECK_EQUAL(loaded.group,           orig.group);
    BOOST_CHECK_EQUAL(loaded.fTrusted,        orig.fTrusted);
    BOOST_CHECK_EQUAL(loaded.connection_type, orig.connection_type);
}

BOOST_AUTO_TEST_CASE(load_udp_peers_missing_file)
{
    const fs::path nonexistent = m_path_root / "nonexistent_udppeers.dat";
    BOOST_CHECK_NO_THROW(LoadUDPPeers(nonexistent));
}

// mapPersistentNodes is static inside udpnet.cpp so we cannot assert the
// loaded values here. A future test accessor could close that gap.
BOOST_AUTO_TEST_CASE(dump_load_udp_peers_file_format)
{
    const fs::path peers_path = m_path_root / "test_udppeers.dat";

    UDPPeerEntry e1;
    e1.addr_str        = "192.168.1.1:8444";
    e1.local_magic     = 0x1111111111111111ULL;
    e1.remote_magic    = 0x2222222222222222ULL;
    e1.group           = 0;
    e1.fTrusted        = false;
    e1.connection_type = static_cast<uint8_t>(UDP_CONNECTION_TYPE_NORMAL);

    UDPPeerEntry e2;
    e2.addr_str        = "10.0.0.1:9000";
    e2.local_magic     = 0xaabbccddeeff0011ULL;
    e2.remote_magic    = 0xffeeddccbbaa9988ULL;
    e2.group           = 1;
    e2.fTrusted        = true;
    e2.connection_type = static_cast<uint8_t>(UDP_CONNECTION_TYPE_OUTBOUND_ONLY);

    const std::vector<UDPPeerEntry> peers{e1, e2};

    {
        FILE* file = fsbridge::fopen(peers_path, "wb");
        AutoFile fileout{file};
        BOOST_REQUIRE(!fileout.IsNull());
        HashedSourceWriter hashwriter{fileout};
        hashwriter << Params().MessageStart() << peers;
        fileout << hashwriter.GetHash();
        BOOST_REQUIRE(fileout.Commit());
        (void)fileout.fclose();
    }

    BOOST_CHECK_NO_THROW(LoadUDPPeers(peers_path));
}

BOOST_AUTO_TEST_SUITE_END()
