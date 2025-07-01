// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

// This is the external API to FIBRE for use in RPC/validation/etc

#ifndef BITCOIN_UDPAPI_H
#define BITCOIN_UDPAPI_H

#include <netaddress.h>
#include <node/context.h>

class CBlock;

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts(); // port, outbound bandwidth for group
bool InitializeUDPConnections(node::NodeContext* const node_context);
void StopUDPConnections();

enum UDPConnectionType {
    UDP_CONNECTION_TYPE_NORMAL,
    UDP_CONNECTION_TYPE_OUTBOUND_ONLY,
    UDP_CONNECTION_TYPE_INBOUND_ONLY,
};

// fUltimatelyTrusted means you trust them (ie whitelist) and ALL OF THEIR SUBSEQUENT WHITELISTED PEERS
void OpenUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL, size_t group = 0);
void OpenPersistentUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type = UDP_CONNECTION_TYPE_NORMAL, size_t group = 0);

void CloseUDPConnectionTo(const CService& remote_addr);

struct UDPConnectionStats {
    CService remote_addr;
    size_t group;
    bool fUltimatelyTrusted;
    int64_t lastRecvTime;
    std::vector<double> last_pings;
};
void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list);

void UDPRelayBlock(const CBlock& block);

#endif
