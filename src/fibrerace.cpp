// Copyright (c) 2025
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fibrerace.h>

#include <logging.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/trace.h>
// USDT tracepoint semaphores for UDP metrics
TRACEPOINT_SEMAPHORE(udp, block_race_winner);
TRACEPOINT_SEMAPHORE(udp, block_race_time);

#include <chrono>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>

namespace {

struct FibreBlockRaceInfo {
    bool udp_start_set{false};
    std::chrono::steady_clock::time_point udp_start;
    std::string udp_peer;

    bool cmpct_start_set{false};
    std::chrono::steady_clock::time_point cmpct_start;
    std::string cmpct_peer;
};

struct FibreBlockRaceConnectContext {
    bool set{false};
    uint256 hash;
    std::string mechanism;
    std::string peer;
};

Mutex g_block_race_mutex;
std::map<uint256, FibreBlockRaceInfo> g_block_race GUARDED_BY(g_block_race_mutex);

// Prevent late-arriving loser-path "start" events from re-creating entries after
// the winner already logged/cleared them.
constexpr size_t MAX_RECENT_CONNECTED{2048};
std::deque<uint256> g_recent_connected_order GUARDED_BY(g_block_race_mutex);
std::set<uint256> g_recent_connected_set GUARDED_BY(g_block_race_mutex);

thread_local FibreBlockRaceConnectContext g_block_race_ctx;

static double ToMillis(const std::chrono::steady_clock::duration& d)
{
    return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(d).count();
}

static std::string FormatMs(const std::optional<double>& ms)
{
    if (!ms.has_value()) return "n/a";
    return strprintf("%.2fms", *ms);
}

static bool IsRecentlyConnected(const uint256& h) EXCLUSIVE_LOCKS_REQUIRED(g_block_race_mutex)
{
    return g_recent_connected_set.find(h) != g_recent_connected_set.end();
}

static void MarkRecentlyConnected(const uint256& h) EXCLUSIVE_LOCKS_REQUIRED(g_block_race_mutex)
{
    if (g_recent_connected_set.insert(h).second) {
        g_recent_connected_order.push_back(h);
        if (g_recent_connected_order.size() > MAX_RECENT_CONNECTED) {
            const uint256 old = g_recent_connected_order.front();
            g_recent_connected_order.pop_front();
            g_recent_connected_set.erase(old);
        }
    }
}

} // namespace

void FibreBlockRaceRecordUDPStart(const uint256& block_hash,
                                 const std::string& peer,
                                 const std::chrono::steady_clock::time_point& start)
{
    LOCK(g_block_race_mutex);
    if (IsRecentlyConnected(block_hash)) return;
    FibreBlockRaceInfo& info = g_block_race[block_hash];
    if (!info.udp_start_set || start < info.udp_start) {
        info.udp_start_set = true;
        info.udp_start = start;
        info.udp_peer = peer;
    }
}

void FibreBlockRaceRecordCmpctStart(const uint256& block_hash,
                                   const std::string& peer,
                                   const std::chrono::steady_clock::time_point& start)
{
    LOCK(g_block_race_mutex);
    if (IsRecentlyConnected(block_hash)) return;
    FibreBlockRaceInfo& info = g_block_race[block_hash];
    if (!info.cmpct_start_set || start < info.cmpct_start) {
        info.cmpct_start_set = true;
        info.cmpct_start = start;
        info.cmpct_peer = peer;
    }
}

void FibreBlockRaceSetConnectContext(const uint256& block_hash,
                                     const std::string& mechanism,
                                     const std::string& peer)
{
    g_block_race_ctx.set = true;
    g_block_race_ctx.hash = block_hash;
    g_block_race_ctx.mechanism = mechanism;
    g_block_race_ctx.peer = peer;
}

void FibreBlockRaceClearConnectContext()
{
    g_block_race_ctx.set = false;
    g_block_race_ctx.hash.SetNull();
    g_block_race_ctx.mechanism.clear();
    g_block_race_ctx.peer.clear();
}

void FibreBlockRaceNotifyConnected(const uint256& block_hash,
                                   int height,
                                   const std::chrono::steady_clock::time_point& connected_time)
{
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);

    if (!g_block_race_ctx.set || g_block_race_ctx.hash != block_hash) return;

    FibreBlockRaceInfo info;
    bool have_info{false};
    {
        LOCK(g_block_race_mutex);
        MarkRecentlyConnected(block_hash);
        auto it = g_block_race.find(block_hash);
        if (it != g_block_race.end()) {
            info = it->second;
            g_block_race.erase(it);
            have_info = true;
        }
    }

    std::optional<double> udp_ms;
    std::optional<double> cmpct_ms;
    std::string udp_peer;
    std::string cmpct_peer;
    if (have_info) {
        if (info.udp_start_set && connected_time >= info.udp_start) {
            udp_ms = ToMillis(connected_time - info.udp_start);
        }
        if (info.cmpct_start_set && connected_time >= info.cmpct_start) {
            cmpct_ms = ToMillis(connected_time - info.cmpct_start);
        }
        udp_peer = info.udp_peer;
        cmpct_peer = info.cmpct_peer;
    }

    const std::string winner = (g_block_race_ctx.mechanism == "udp") ? "FIBRE/UDP" :
                               (g_block_race_ctx.mechanism == "cmpctblock") ? "BIP152/CMPCTBLOCK" :
                               g_block_race_ctx.mechanism;

    if (fBench) {
        LogPrintf("UDP: block=%s height=%d winner=%s winner_peer=%s udp=%s udp_peer=%s cmpct=%s cmpct_peer=%s\n",
              block_hash.ToString(),
              height,
              winner,
              g_block_race_ctx.peer.empty() ? "n/a" : g_block_race_ctx.peer,
              FormatMs(udp_ms),
              udp_peer.empty() ? "n/a" : udp_peer,
              FormatMs(cmpct_ms),
              cmpct_peer.empty() ? "n/a" : cmpct_peer);
    }

    bool trace_active_cw = TRACEPOINT_ACTIVE(udp, block_race_winner);

    if (trace_active_cw) {
        // Emit tracepoint for block race outcome (UDP vs compact block)
        TRACEPOINT(udp, block_race_winner,
            block_hash.data(),                      // Block hash (32 bytes)
            (int)height,                            // Block height
            winner.c_str(),                         // Winner mechanism string
            g_block_race_ctx.peer.empty() ? "n/a" : g_block_race_ctx.peer.c_str()   // Winner peer
        );
    }

    bool trace_active_ct = TRACEPOINT_ACTIVE(udp, block_race_time);

    if (trace_active_ct) {
        int64_t udp_ns = info.udp_start_set && connected_time >= info.udp_start 
                    ? Ticks<std::chrono::nanoseconds>(connected_time - info.udp_start)
                    : -1;
        int64_t cmpct_ns = info.cmpct_start_set && connected_time >= info.cmpct_start 
                        ? Ticks<std::chrono::nanoseconds>(connected_time - info.cmpct_start)
                        : -1;
                        
        // Emit tracepoint for block race outcome (UDP vs compact block)
        TRACEPOINT(udp, block_race_time,
            block_hash.data(),                      // Block hash (32 bytes)
            (int)height,                            // Block height
            udp_ns,                                 // UDP path time (ns or -1)
            udp_peer.empty() ? "n/a" : udp_peer.c_str(),   // UDP peer
            cmpct_ns,                               // Compact block path time (ns or -1)
            cmpct_peer.empty() ? "n/a" : cmpct_peer.c_str() // Compact block peer
        );
    }
}

