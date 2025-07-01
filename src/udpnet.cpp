// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udpnet.h>
#include <udpapi.h>
#include <udprelay.h>

#include <common/args.h>
#include <compat/endian.h>
#include <crypto/poly1305.h>
#include <hash.h>
#include <logging.h>
#include <netbase.h>
#include <util/strencodings.h>
#include <common/system.h>
#include <util/thread.h>
#include <util/time.h>

#include <fibre/udp_socket.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <span>
#include <thread>

#ifndef WIN32
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static std::vector<std::shared_ptr<fibre::DatagramSocket>> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
std::atomic<uint64_t> min_per_node_mbps(1024);
std::atomic_bool maybe_have_write_nodes{false};

static std::map<int64_t, std::tuple<CService, uint64_t, size_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static node::NodeContext* g_node_context; // Initialized by InitializeUDPConnections

// TODO: The checksum stuff is not endian-safe (esp the poly impl):
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length)
{
    assert(length <= sizeof(UDPMessage));

    uint8_t key[Poly1305::KEYLEN]; // (32 bytes)
    memcpy(key, &magic, sizeof(magic));
    memcpy(key + 8, &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[Poly1305::TAGLEN]; // (16 bytes)

    // Create Poly1305 object with key and compute hash
    Poly1305 poly1305{std::span<const std::byte>{reinterpret_cast<const std::byte*>(key), Poly1305::KEYLEN}};
    poly1305.Update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&msg.header.msg_type), length - 16});
    poly1305.Finalize(std::span<std::byte>{reinterpret_cast<std::byte*>(hash), Poly1305::TAGLEN});

    memcpy(&msg.header.chk1, hash, sizeof(msg.header.chk1));
    memcpy(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));

    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type)[i + j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }
}

static bool CheckChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length)
{
    assert(length <= sizeof(UDPMessage));
    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type)[i + j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }

    uint8_t key[Poly1305::KEYLEN]; // (32 bytes)
    memcpy(key, &magic, sizeof(magic));
    memcpy(key + 8, &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[Poly1305::TAGLEN]; // (16 bytes)

    // Create Poly1305 object with key and compute hash
    Poly1305 poly1305{std::span<const std::byte>{reinterpret_cast<const std::byte*>(key), Poly1305::KEYLEN}};
    poly1305.Update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&msg.header.msg_type), length - 16});
    poly1305.Finalize(std::span<std::byte>{reinterpret_cast<std::byte*>(hash), Poly1305::TAGLEN});

    return !memcmp(&msg.header.chk1, hash, sizeof(msg.header.chk1)) && !memcmp(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));
}

/**
 * Init/shutdown logic follows
 */

// Sockets and the loop are owned until all UDP workers have joined.
static std::unique_ptr<fibre::ReadLoop> read_loop;
static void do_send_messages();
static void send_messages_stop();
static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t>>& group_list);
static void read_socket_func(const fibre::DatagramSocket& socket);
static void timer_func();
static std::unique_ptr<std::thread> udp_read_thread;
static std::vector<std::thread> udp_write_threads;

static void AddConnectionFromString(const std::string& node, bool fTrust) {
    size_t host_port_end = node.find(',');
    size_t local_pass_end = node.find(',', host_port_end + 1);
    size_t remote_pass_end = node.find(',', local_pass_end + 1);
    size_t group_end = node.find(',', remote_pass_end + 1);
    if (host_port_end == std::string::npos || local_pass_end == std::string::npos || (remote_pass_end != std::string::npos && group_end != std::string::npos)) {
        LogInfo("UDP: Failed to parse parameter to -add[trusted]udpnode");
        return;
    }

    std::string host_port = node.substr(0, host_port_end);
    std::optional<CService> addr = Lookup(host_port.c_str(), -1, true);
    if (!addr.has_value()) {
        LogInfo("UDP: Failed to lookup hostname for -add[trusted]udpnode");
        return;
    }

    std::string local_pass = node.substr(host_port_end + 1, local_pass_end - host_port_end - 1);
    uint64_t local_magic = Hash(local_pass).GetUint64(0);

    std::string remote_pass;
    if(remote_pass_end == std::string::npos)
        remote_pass = node.substr(local_pass_end + 1);
    else
        remote_pass = node.substr(local_pass_end + 1, remote_pass_end - local_pass_end - 1);
    uint64_t remote_magic = Hash(remote_pass).GetUint64(0);

    size_t group = 0;
    if (remote_pass_end != std::string::npos) {
        std::string group_str(node.substr(remote_pass_end + 1));
        group = LocaleIndependentAtoi<int>(group_str);
    }

    if (group >= GetUDPInboundPorts().size() || !(addr->IsIPv4() || addr->IsIPv6())) {
        LogError("UDP: invalid address or group in configured peer");
        return;
    }
    OpenPersistentUDPConnectionTo(addr.value(), local_magic, remote_magic, fTrust, UDP_CONNECTION_TYPE_NORMAL, group);
}

static void AddConfAddedConnections() {
    if (gArgs.IsArgSet("-addudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addudpnode")) {
            AddConnectionFromString(node, false);
        }
    }
    if (gArgs.IsArgSet("-addtrustedudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addtrustedudpnode")) {
            AddConnectionFromString(node, true);
        }
    }
}

bool InitializeUDPConnections(node::NodeContext* const node_context)
{
    assert(udp_write_threads.empty() && !udp_read_thread && udp_socks.empty());
    const auto group_list{GetUDPInboundPorts()};
    if (group_list.empty()) return !gArgs.IsArgSet("-udpport");
    g_node_context = node_context;

    // UDP does not need SO_REUSEADDR for restarts. Exclusive bindings also
    // prevent two daemons from silently receiving each other's datagrams.
    auto failed = [] {
        LogError("UDP: startup failed: %s", NetworkErrorString(WSAGetLastError()));
        StopUDPConnections();
        return false;
    };
    // A millisecond-sized sender burst can exceed the platform's default
    // receive queue at gigabit rates. This is a best-effort bounded request;
    // the operating system may clamp it to its configured maximum.
    const int receive_buffer_size{4 * 1024 * 1024};
    for (const auto& [port, bandwidth] : group_list) {
        auto socket6{fibre::DatagramSocket::Create(AF_INET6)};
        if (!socket6) return failed();
        if (socket6->SetSockOpt(SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, sizeof(receive_buffer_size)) != 0)
            LogDebug(BCLog::UDPNET, "UDP: could not enlarge IPv6 receive buffer");
        const int only_v6{1};
        if (socket6->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, &only_v6, sizeof(only_v6)) != 0) return failed();
        sockaddr_in6 address6{};
        address6.sin6_family = AF_INET6;
        address6.sin6_addr = in6addr_any;
        address6.sin6_port = htons(port);
        if (socket6->Bind(reinterpret_cast<const sockaddr*>(&address6), sizeof(address6)) != 0) return failed();
        udp_socks.push_back(std::move(socket6));

        auto socket4{fibre::DatagramSocket::Create(AF_INET)};
        if (!socket4) return failed();
        if (socket4->SetSockOpt(SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, sizeof(receive_buffer_size)) != 0)
            LogDebug(BCLog::UDPNET, "UDP: could not enlarge IPv4 receive buffer");
        sockaddr_in address4{};
        address4.sin_family = AF_INET;
        address4.sin_addr.s_addr = htonl(INADDR_ANY);
        address4.sin_port = htons(port);
        if (socket4->Bind(reinterpret_cast<const sockaddr*>(&address4), sizeof(address4)) != 0) return failed();
        udp_socks.push_back(std::move(socket4));
        LogInfo("UDP: Bound to port %hu for group %zu with %lu Mbps", port, udp_socks.size() / 2 - 1, bandwidth);
    }
    read_loop = fibre::ReadLoop::Create();
    if (!read_loop) return failed();
    send_messages_init(group_list);
    try {
        BlockRecvInit(node_context);
        udp_write_threads.emplace_back(&util::TraceThread, "udpwrite", &do_send_messages);
        AddConfAddedConnections();
        udp_read_thread = std::make_unique<std::thread>(&util::TraceThread, "udpread", [] {
            read_loop->Run(udp_socks, read_socket_func, timer_func);
        });
    } catch (const std::exception& e) {
        LogError("UDP: worker startup failed: %s", e.what());
        StopUDPConnections();
        return false;
    }
    return true;
}

void StopUDPConnections()
{
    if (read_loop) read_loop->Interrupt();
    if (udp_read_thread) {
        udp_read_thread->join();
        udp_read_thread.reset();
    }
    // Exclude new relay work before joining the decoder. Do not hold the node
    // map mutex while joining: validation can call back into UDPRelayBlock.
    {
        std::lock_guard<std::recursive_mutex> lock(cs_mapUDPNodes);
        maybe_have_write_nodes = false;
    }
    BlockRecvShutdown();
    {
        std::lock_guard<std::recursive_mutex> lock(cs_mapUDPNodes);
        send_messages_stop();
        for (auto& thread : udp_write_threads) thread.join();
        udp_write_threads.clear();

        // Notify peers after the sender stops, so queued block data cannot
        // follow the disconnect. Attempt one nonblocking send per peer: do not
        // wait for pacing, drain the backlog, or retry failed control packets.
        for (const auto& [service, state] : mapUDPNodes) {
            const auto& connection{state.connection};
            if (connection.group >= udp_socks.size() / 2) continue;

            sockaddr_storage address{};
            socklen_t address_len{sizeof(address)};
            if (!service.GetSockAddr(reinterpret_cast<sockaddr*>(&address), &address_len)) continue;

            UDPMessage msg;
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            FillChecksum(connection.remote_magic, msg, sizeof(UDPMessageHeader));
            const auto& socket{udp_socks[connection.group * 2 + (service.IsIPv6() ? 0 : 1)]};
            if (socket->SendTo(&msg, sizeof(UDPMessageHeader), reinterpret_cast<const sockaddr*>(&address), address_len) != sizeof(UDPMessageHeader)) {
                LogDebug(BCLog::UDPNET, "UDP: shutdown disconnect send failed: %s", NetworkErrorString(WSAGetLastError()));
            }
        }
        mapUDPNodes.clear();
        mapPersistentNodes.clear();
        nodesToRepeatDisconnect.clear();
        udp_socks.clear();
        read_loop.reset();
        g_node_context = nullptr;
        min_per_node_mbps = 1024;
    }
}

// ---

/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), false, it);

    int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second);

    return silent_disconnect(it);
}

void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it) {
    send_and_disconnect(it);
}

static void read_socket_func(const fibre::DatagramSocket& socket) {
    const bool fBench = util::log::ShouldDebugLog(BCLog::BENCH);
    std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

    UDPMessage msg;
    sockaddr_storage remote_addr;
    socklen_t remote_addr_len = sizeof(remote_addr);
    ssize_t res = socket.RecvFrom(&msg, sizeof(msg), reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);

    if (res < 0) {
        const int err{WSAGetLastError()};
        if (err != WSAEWOULDBLOCK && err != WSAEINTR && err != WSAEMSGSIZE)
            LogDebug(BCLog::UDPNET, "UDP: receive failed: %s", NetworkErrorString(err));
        return;
    }

    if (size_t(res) < sizeof(UDPMessageHeader) || size_t(res) >= sizeof(UDPMessage))
        return;

    CService remote_service;
    if (((sockaddr*)&remote_addr)->sa_family == AF_INET6) {
        remote_service = CService(*(sockaddr_in6*)&remote_addr);
    } else if (((sockaddr*)&remote_addr)->sa_family == AF_INET) {
        remote_service = CService(*(sockaddr_in*)&remote_addr);
    } else {
        return;
    }
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapUDPNodes.find(remote_service);
    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res))
        return;

    UDPConnectionState& state = it->second;

    const uint8_t msg_type_masked = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK);

    state.lastRecvTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    state.lastRecvSteadyTime = TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
    if (msg_type_masked == MSG_TYPE_SYN) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogInfo("UDP: Got invalidly-sized SYN message from %s\n", UDPLogPeer(it->first));
            send_and_disconnect(it);
            return;
        }

        state.protocolVersion = static_cast<uint32_t>(le64toh_internal(msg.msg.longint));
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > PROTOCOL_VERSION_CUR(UDP_PROTOCOL_VERSION)) {
            LogInfo("UDP: Got min protocol version we didn't understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), UDPLogPeer(it->first));
            send_and_disconnect(it);
            return;
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogInfo("UDP: Got invalidly-sized KEEPALIVE message from %s\n", UDPLogPeer(it->first));
            send_and_disconnect(it);
            return;
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogDebug(BCLog::UDPNET, "UDP: Successfully connected to %s!\n", UDPLogPeer(it->first));

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_DISCONNECT) {
        LogInfo("UDP: Got disconnect message from %s\n", UDPLogPeer(it->first));
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg_type_masked == MSG_TYPE_BLOCK_HEADER || msg_type_masked == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockMessage(msg, res, it->first, it->second, start, g_node_context, BlockMessageOrigin::NETWORK)) {
            send_and_disconnect(it);
            return;
        }
    } else if (msg_type_masked == MSG_TYPE_TX_CONTENTS) {
        LogInfo("UDP: Got tx message over the wire from %s, this isn't supposed to happen!\n", UDPLogPeer(it->first));
        send_and_disconnect(it);
        return;
    } else if (msg_type_masked == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogInfo("UDP: Got invalidly-sized PING message from %s\n", UDPLogPeer(it->first));
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
    } else if (msg_type_masked == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogInfo("UDP: Got invalidly-sized PONG message from %s\n", UDPLogPeer(it->first));
            send_and_disconnect(it);
            return;
        }

        uint64_t nonce = le64toh_internal(msg.msg.longint);
        std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.find(nonce);
        if (nonceit == state.ping_times.end()) // Possibly duplicated packet
            LogInfo("UDP: Got PONG message without PING from %s\n", UDPLogPeer(it->first));
        else {
            int64_t timeMicros = TicksSinceEpoch<std::chrono::microseconds>(SteadyClock::now());
            double rtt = (timeMicros - nonceit->second) / 1000.0;
            LogInfo("UDP: RTT to %s is %lf ms\n", UDPLogPeer(it->first), rtt);
            state.ping_times.erase(nonceit);
            state.last_pings[state.last_ping_location] = rtt;
            state.last_ping_location = (state.last_ping_location + 1) % (sizeof(state.last_pings) / sizeof(double));
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
        if (to_millis_double(finish - start) > 1)
            LogInfo("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info);
static void timer_func() {
    ProcessDownloadTimerEvents();

    UDPMessage msg;
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    {
        std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::iterator itend = nodesToRepeatDisconnect.upper_bound(now);
        for (std::map<int64_t, std::tuple<CService, uint64_t, size_t> >::const_iterator it = nodesToRepeatDisconnect.begin(); it != itend; it++) {
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            SendMessage(msg, sizeof(UDPMessageHeader), false, std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second));
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {
        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_NORMAL) {
            it++;
            continue;
        }

        UDPConnectionState& state = it->second;

        int64_t origLastSendTime = state.lastSendTime;

        if (state.lastRecvSteadyTime < now - 1000 * 60 * 10) {
            LogDebug(BCLog::UDPNET, "UDP: Peer %s timed out\n", UDPLogPeer(it->first));
            it = send_and_disconnect(it); // Removes it from mapUDPNodes
            continue;
        }

        if (!(state.state & STATE_GOT_SYN_ACK) && origLastSendTime < now - 1000) {
            msg.header.msg_type = MSG_TYPE_SYN;
            msg.msg.longint = htole64_internal(UDP_PROTOCOL_VERSION);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), false, it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = FastRandomContext().rand64();
            msg.header.msg_type = MSG_TYPE_PING;
            msg.msg.longint = htole64_internal(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, it);
            state.ping_times[pingnonce] = TicksSinceEpoch<std::chrono::microseconds>(SteadyClock::now());
            state.lastPingTime = now;
        }

        for (std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.begin(); nonceit != state.ping_times.end();) {
            if (nonceit->second < (now - 5000) * 1000)
                nonceit = state.ping_times.erase(nonceit);
            else
                nonceit++;
        }

        it++;
    }

    for (const auto& conn : mapPersistentNodes) {
        if (!mapUDPNodes.count(conn.first)) {
            bool fWaitingOnDisconnect = false;
            for (const auto& repeatNode : nodesToRepeatDisconnect) {
                if (std::get<0>(repeatNode.second) == conn.first)
                    fWaitingOnDisconnect = true;
            }
            if (fWaitingOnDisconnect)
                continue;

            OpenUDPConnectionTo(conn.first, conn.second);
        }
    }
}

// ~10MB of outbound messages pending
#define PENDING_MESSAGES_BUFF_SIZE 8192
static std::atomic_bool send_messages_break(false);
std::mutex send_messages_mutex;
std::condition_variable send_messages_wake_cv;
struct PendingMessagesBuff {
    std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
    std::atomic<uint16_t> nextPendingMessage, nextUndefinedMessage;
    PendingMessagesBuff() : nextPendingMessage(0), nextUndefinedMessage(0) {}
};
struct MessageStateCache {
    ssize_t buff_id;
    uint16_t nextPendingMessage;
    uint16_t nextUndefinedMessage;
};
struct PerGroupMessageQueue {
    std::array<PendingMessagesBuff, 2> buffs;
    inline MessageStateCache NextBuff(std::memory_order order) {
        for (size_t i = 0; i < buffs.size(); i++) {
            uint16_t next_undefined_message = buffs[i].nextUndefinedMessage.load(order);
            uint16_t next_pending_message = buffs[i].nextPendingMessage.load(order);
            if (next_undefined_message != next_pending_message)
                return {(ssize_t)i, next_pending_message, next_undefined_message};
        }
        return {-1, 0, 0};
    }
    uint64_t bw;
    PerGroupMessageQueue() : bw(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) = delete;
};
static std::vector<PerGroupMessageQueue> messageQueues;
static const size_t LOCAL_RECEIVE_GROUP = (size_t)-1;

static inline void SendMessage(const UDPMessage& msg, const unsigned int length, PendingMessagesBuff& buff, const CService& service, const uint64_t magic) {
    std::unique_lock<std::mutex> lock(send_messages_mutex);
    const uint16_t next_undefined_message_cache = buff.nextUndefinedMessage.load(std::memory_order_acquire);
    const uint16_t next_pending_message_cache = buff.nextPendingMessage.load(std::memory_order_acquire);
    if (next_pending_message_cache == (next_undefined_message_cache + 1) % PENDING_MESSAGES_BUFF_SIZE)
        return;

    std::tuple<CService, UDPMessage, unsigned int, uint64_t>& new_msg = buff.messagesPendingRingBuff[next_undefined_message_cache];
    std::get<0>(new_msg) = service;
    memcpy(&std::get<1>(new_msg), &msg, length);
    std::get<2>(new_msg) = length;
    std::get<3>(new_msg) = magic;

    bool need_notify = next_undefined_message_cache == next_pending_message_cache;
    buff.nextUndefinedMessage.store((next_undefined_message_cache + 1) % PENDING_MESSAGES_BUFF_SIZE, std::memory_order_release);

    lock.unlock();
    if (need_notify)
        send_messages_wake_cv.notify_all();
}

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group) {
    assert(length <= sizeof(UDPMessage));

    if (group == LOCAL_RECEIVE_GROUP)
        return;

    assert(group < messageQueues.size());
    PerGroupMessageQueue& queue = messageQueues[group];
    PendingMessagesBuff& buff = high_prio ? queue.buffs[0] : queue.buffs[1];

    SendMessage(msg, length, buff, service, magic);
}
void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::map<CService, UDPConnectionState>::const_iterator& node) {
    SendMessage(msg, length, high_prio, node->first, node->second.connection.remote_magic, node->second.connection.group);
}

struct PerQueueSendState {
    MessageStateCache buff_state;
    std::chrono::steady_clock::time_point next_send;
    size_t write_objs_per_call, bytes_per_obj, target_bytes_per_sec;
    bool buff_emptied;
};

static inline bool fill_cache(PerQueueSendState* states, std::chrono::steady_clock::time_point& now) {
    bool have_work = false;
    for (size_t i = 0; i < messageQueues.size(); i++) {
        if (states[i].next_send > now)
            continue;

        states[i].buff_state = messageQueues[i].NextBuff(std::memory_order_acquire);
        if (states[i].buff_state.buff_id != -1) {
            have_work = true;
            break;
        }
    }
    return have_work;
}

static void do_send_messages() {
#ifndef WIN32
    {
        struct sched_param sched = {};
        sched.sched_priority = sched_get_priority_max(SCHED_RR);
        int res = pthread_setschedparam(pthread_self(), SCHED_RR, &sched);
        LogInfo("UDP: %s write thread priority to SCHED_RR%s\n", !res ? "Set" : "Was unable to set", !res ? "" : (res == EPERM ? " (permission denied)" : " (other error)"));
        if (res) {
            errno = 0;
            res = nice(-20);
            LogInfo("UDP: %s write thread nice value to %d%s\n", !errno ? "Set" : "Was unable to set", res, !errno ? "" : (errno == EPERM ? " (permission denied)" : " (other error)"));
        }
    }
#endif

    static const size_t WRITES_PER_SEC = 1000;

    std::vector<PerQueueSendState> states(messageQueues.size());
    for (size_t i = 0; i < messageQueues.size(); i++) {
        states[i].buff_state           = {-1, 0, 0};
        states[i].next_send            = std::chrono::steady_clock::now();
        states[i].target_bytes_per_sec = messageQueues[i].bw * 1024 * 1024 / 8;
        states[i].bytes_per_obj        = PACKET_SIZE;
        states[i].write_objs_per_call  = std::max<size_t>(1, states[i].target_bytes_per_sec / WRITES_PER_SEC / states[i].bytes_per_obj / messageQueues.size());
        states[i].buff_emptied         = true;
    }

    while (true) {
        std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());
        if (send_messages_break)
            return;
        std::chrono::steady_clock::time_point sleep_until(start + std::chrono::minutes(60));

        for (size_t group = 0; group < messageQueues.size(); group++) {
            PerQueueSendState& send_state = states[group];
            if (send_state.next_send > start) {
                sleep_until = std::min(sleep_until, send_state.next_send);
                continue;
            }

            size_t extra_writes = 0;
            if (!send_state.buff_emptied) {
                static_assert(std::is_same<std::chrono::steady_clock::time_point::period, std::nano>::value, "Better to math you with");
                extra_writes = std::chrono::nanoseconds(start - send_state.next_send).count() * WRITES_PER_SEC * send_state.write_objs_per_call / std::nano::den;
            }

            if (send_state.buff_state.buff_id == -1 || // Skip if we got filled in in the locked check...
                    send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage || // ...or we're out of known messages
                    send_state.buff_state.buff_id == 0) // ...or we want to check for availability in a higher-priority buffer
                send_state.buff_state = messageQueues[group].NextBuff(std::memory_order_acquire);
            if (send_state.buff_state.buff_id == -1) {
                send_state.buff_emptied = true;
                continue;
            }

            PendingMessagesBuff* buff = &messageQueues[group].buffs[send_state.buff_state.buff_id];
            size_t i = 0;
            for (; i < send_state.write_objs_per_call + extra_writes && send_state.buff_state.buff_id != -1; i++) {
                std::tuple<CService, UDPMessage, unsigned int, uint64_t>& msg = buff->messagesPendingRingBuff[send_state.buff_state.nextPendingMessage];

                FillChecksum(std::get<3>(msg), std::get<1>(msg), std::get<2>(msg));

                // Set destination address. Connection entry points only admit
                // IPv4 and IPv6 peers; drop anything else rather than abort.
                const CService& service{std::get<0>(msg)};
                sockaddr_storage ss{};
                socklen_t addrlen{sizeof(ss)};
                if (service.GetSockAddr(reinterpret_cast<sockaddr*>(&ss), &addrlen)) {
                    const auto& sendSock = udp_socks[group * 2 + (service.IsIPv6() ? 0 : 1)];
                    if (sendSock->SendTo(&std::get<1>(msg), std::get<2>(msg), reinterpret_cast<const sockaddr*>(&ss), addrlen) != std::get<2>(msg)) {
                        LogDebug(BCLog::UDPNET, "UDP: send failed: %s", NetworkErrorString(WSAGetLastError()));
                    }
                }

                send_state.buff_state.nextPendingMessage = (send_state.buff_state.nextPendingMessage + 1) % PENDING_MESSAGES_BUFF_SIZE;
                if (send_state.buff_state.nextPendingMessage == send_state.buff_state.nextUndefinedMessage) {
                    buff->nextPendingMessage.store(send_state.buff_state.nextPendingMessage, std::memory_order_release);
                    send_state.buff_state = messageQueues[group].NextBuff(std::memory_order_acquire);
                    if (send_state.buff_state.buff_id != -1)
                        buff = &messageQueues[group].buffs[send_state.buff_state.buff_id];
                }
            }
            if (send_state.buff_state.buff_id != -1)
                buff->nextPendingMessage.store(send_state.buff_state.nextPendingMessage, std::memory_order_release);
            size_t non_extra_messages_sent = std::max<ssize_t>(std::min(i, send_state.write_objs_per_call), ssize_t(i) - extra_writes);
            send_state.next_send = start + std::chrono::nanoseconds(1000ULL*1000*1000 * send_state.bytes_per_obj * non_extra_messages_sent / send_state.target_bytes_per_sec);
            send_state.buff_emptied = false;
            sleep_until = std::min(sleep_until, send_state.next_send);
        }

        std::chrono::steady_clock::time_point end(std::chrono::steady_clock::now());
        if (sleep_until > end) { // No need to be aggressive here, fill_cache is useful to speed up per-queue loop anyway
            if (fill_cache(states.data(), end))
                continue;
            std::unique_lock<std::mutex> lock(send_messages_mutex);
            if (!send_messages_break && !fill_cache(states.data(), end))
                send_messages_wake_cv.wait_until(lock, sleep_until);
        }
    }
}

static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list) {
    send_messages_break = false;
    messageQueues = std::vector<PerGroupMessageQueue>(group_list.size());
    for (size_t i = 0; i < group_list.size(); i++)
        messageQueues[i].bw = group_list[i].second;
}

static void send_messages_stop() {
    // Cancel queued datagrams; shutdown must not wait for bandwidth pacing.
    {
        std::lock_guard<std::mutex> lock(send_messages_mutex);
        send_messages_break = true;
    }
    send_messages_wake_cv.notify_all();
}

/**
 * Public API follows
 */

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts()
{
    if (!gArgs.IsArgSet("-udpport")) return std::vector<std::pair<unsigned short, uint64_t> >();

    std::map<size_t, std::pair<unsigned short, uint64_t> > res;
    for (const std::string& s : gArgs.GetArgs("-udpport")) {
        size_t port_end = s.find(',');
        size_t group_end = s.find(',', port_end + 1);
        size_t bw_end = s.find(',', group_end + 1);

        if (port_end == std::string::npos || (group_end != std::string::npos && bw_end != std::string::npos)) {
            LogInfo("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t port = LocaleIndependentAtoi<int>(s.substr(0, port_end));
        if (port != (unsigned short)port || port == 0) {
            LogInfo("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t group = LocaleIndependentAtoi<int>(s.substr(port_end + 1, group_end - port_end - 1));
        if (group < 0 || res.count(group)) {
            LogInfo("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }

        int64_t bw = 1024;
        if (group_end != std::string::npos) {
            bw = LocaleIndependentAtoi<int>(s.substr(group_end + 1));
            if (bw <= 0) {
                LogInfo("Failed to parse -udpport option, not starting FIBRE\n");
                return std::vector<std::pair<unsigned short, uint64_t> >();
            }
        }

        res[group] = std::make_pair((unsigned short)port, uint64_t(bw));
    }

    std::vector<std::pair<unsigned short, uint64_t> > v;
    for (size_t i = 0; i < res.size(); i++) {
        if (!res.count(i)) {
            LogInfo("Failed to parse -udpport option, not starting FIBRE\n");
            return std::vector<std::pair<unsigned short, uint64_t> >();
        }
        v.push_back(res[i]);
    }

    return v;
}

void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list) {
    connections_list.clear();
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    connections_list.reserve(mapUDPNodes.size());
    for (const auto& node : mapUDPNodes) {
        connections_list.push_back({node.first, node.second.connection.group, node.second.connection.fTrusted, (node.second.state & STATE_GOT_SYN_ACK) ? node.second.lastRecvTime : 0, {}});
        for (size_t i = 0; i < sizeof(node.second.last_pings) / sizeof(double); i++)
            if (node.second.last_pings[i] != -1)
                connections_list.back().last_pings.push_back(node.second.last_pings[i]);
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    assert(info.group < messageQueues.size());

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    if (info.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
        maybe_have_write_nodes = true;

    LogDebug(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", UDPLogPeer(addr));

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = STATE_INIT;
    state.lastRecvTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    state.lastRecvSteadyTime = TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
    // Preserve an immediate initial SYN and ping even when the monotonic
    // clock's epoch is recent (for example shortly after boot).
    state.lastSendTime = state.lastRecvSteadyTime - 1001;
    state.lastPingTime = state.lastRecvSteadyTime - 1000 * 60 * 15 - 1;

    size_t group_count = 0;
    for (const auto& it : mapUDPNodes)
        if (it.second.connection.group == info.group)
            group_count++;
    min_per_node_mbps = std::min(min_per_node_mbps.load(), messageQueues[info.group].bw / group_count);
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    OpenUDPConnectionTo(addr, {htole64_internal(local_magic), htole64_internal(remote_magic), group, fUltimatelyTrusted, connection_type});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;

    UDPConnectionInfo info = {htole64_internal(local_magic), htole64_internal(remote_magic), group, fUltimatelyTrusted, connection_type};
    OpenUDPConnectionTo(addr, info);
    mapPersistentNodes[addr] = info;
}

void CloseUDPConnectionTo(const CService& addr) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapPersistentNodes.find(addr);
    if (it != mapPersistentNodes.end())
        mapPersistentNodes.erase(it);

    auto it2 = mapUDPNodes.find(addr);
    if (it2 == mapUDPNodes.end())
        return;
    DisconnectNode(it2);
}
