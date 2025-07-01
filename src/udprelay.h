// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <udpnet.h>

void UDPRelayBlock(const CBlock& block);

void BlockRecvInit(ChainstateManager* chainman);

void BlockRecvShutdown();

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const node::NodeContext* const node_context);

void ProcessDownloadTimerEvents();

// Each UDPMessage must be of sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH in length!
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs);
void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<UDPMessage>& msgs);

#endif
