// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <udpnet.h>

// UDPRelayBlock is declared in udpapi.h (included via udpnet.h)

void BlockRecvInit(ChainstateManager* chainman, PeerManager* peer_manager);

void BlockRecvShutdown();

bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const node::NodeContext* const node_context);

void ProcessDownloadTimerEvents();

#endif // BITCOIN_UDPRELAY_H
