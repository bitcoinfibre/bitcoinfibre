// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <udpnet.h>

// UDPRelayBlock is declared in udpapi.h (included via udpnet.h)

void BlockRecvInit(const node::NodeContext* node_context);

void BlockRecvShutdown();

/** Local replay feeds reconstruction without repeating network forwarding. */
enum class BlockMessageOrigin { NETWORK, LOCAL_REPLAY };

bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const node::NodeContext* node_context, BlockMessageOrigin origin);

void ProcessDownloadTimerEvents();

#endif // BITCOIN_UDPRELAY_H
