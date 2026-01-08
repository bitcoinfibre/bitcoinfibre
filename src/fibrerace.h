// Copyright (c) 2025
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FIBRERACE_H
#define BITCOIN_FIBRERACE_H

#include <uint256.h>

#include <chrono>
#include <string>

// Record the earliest observed "start time" for each mechanism.
void FibreBlockRaceRecordUDPStart(const uint256& block_hash,
                                 const std::string& peer,
                                 const std::chrono::steady_clock::time_point& start);
void FibreBlockRaceRecordCmpctStart(const uint256& block_hash,
                                    const std::string& peer,
                                    const std::chrono::steady_clock::time_point& start);

// Set per-thread context identifying the mechanism/peer responsible for the
// ProcessNewBlock() call that (may) connect the block.
void FibreBlockRaceSetConnectContext(const uint256& block_hash,
                                     const std::string& mechanism,
                                     const std::string& peer);
void FibreBlockRaceClearConnectContext();

// Called from validation (ConnectTip) after a block is connected to the active tip.
void FibreBlockRaceNotifyConnected(const uint256& block_hash,
                                   int height,
                                   const std::chrono::steady_clock::time_point& connected_time);

class FibreBlockRaceConnectContextGuard
{
public:
    FibreBlockRaceConnectContextGuard(const uint256& block_hash,
                                      const std::string& mechanism,
                                      const std::string& peer)
    {
        FibreBlockRaceSetConnectContext(block_hash, mechanism, peer);
    }
    FibreBlockRaceConnectContextGuard(const FibreBlockRaceConnectContextGuard&) = delete;
    FibreBlockRaceConnectContextGuard& operator=(const FibreBlockRaceConnectContextGuard&) = delete;
    ~FibreBlockRaceConnectContextGuard() { FibreBlockRaceClearConnectContext(); }
};

#endif // BITCOIN_FIBRERACE_H
