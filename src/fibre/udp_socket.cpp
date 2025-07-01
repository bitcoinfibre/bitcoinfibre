// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <fibre/udp_socket.h>

#include <logging.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <thread>

namespace fibre {

std::shared_ptr<DatagramSocket> DatagramSocket::Create(int family)
{
    const SOCKET socket = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) return {};
    auto result{std::make_shared<DatagramSocket>(socket)};
    if (!result->IsSelectable() || !result->SetNonBlocking()) return {};
    return result;
}

ssize_t DatagramSocket::SendTo(const void* data, size_t size, const sockaddr* address, socklen_t length) const
{
    // All FIBRE datagrams are bounded well below the Windows int length limit.
    assert(size <= std::numeric_limits<int>::max());
    return ::sendto(m_socket, static_cast<const char*>(data), static_cast<int>(size), 0, address, length);
}

ssize_t DatagramSocket::RecvFrom(void* data, size_t size, sockaddr* address, socklen_t* length) const
{
    assert(size <= std::numeric_limits<int>::max());
    return ::recvfrom(m_socket, static_cast<char*>(data), static_cast<int>(size), 0, address, length);
}

std::unique_ptr<ReadLoop> ReadLoop::Create(std::chrono::milliseconds interval)
{
    assert(interval.count() > 0);
    auto wake{DatagramSocket::Create(AF_INET)};
    if (!wake) return {};
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (wake->Bind(reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) return {};
    socklen_t length{sizeof(address)};
    if (wake->GetSockName(reinterpret_cast<sockaddr*>(&address), &length) != 0) return {};
    return std::unique_ptr<ReadLoop>{new ReadLoop{std::move(wake), address, interval}};
}

void ReadLoop::Interrupt()
{
    m_interrupted.store(true, std::memory_order_release);
    const char byte{0};
    (void)m_wake->SendTo(&byte, sizeof(byte), reinterpret_cast<const sockaddr*>(&m_address), sizeof(m_address));
}

void ReadLoop::Run(const std::vector<std::shared_ptr<DatagramSocket>>& sockets,
                   const std::function<void(const DatagramSocket&)>& receive,
                   const std::function<void()>& timer)
{
    Sock::EventsPerSock events;
    events.emplace(m_wake, Sock::Events{Sock::RecvEvent});
    for (const auto& socket : sockets) events.emplace(socket, Sock::Events{Sock::RecvEvent});
    auto deadline{std::chrono::steady_clock::now() + m_interval};
    while (!m_interrupted.load(std::memory_order_acquire)) {
        for (auto& [socket, event] : events) event.occurred = 0;
        const auto remaining{std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())};
        const auto timeout{std::clamp(remaining, std::chrono::milliseconds{0}, m_interval)};
        if (!m_wake->WaitMany(timeout, events)) {
            const int error{WSAGetLastError()};
            if (error != WSAEINTR) {
                LogDebug(BCLog::UDPNET, "UDP: socket wait failed: %s", NetworkErrorString(error));
                // Avoid spinning on a persistent platform error. Interruption
                // remains bounded even when the native wait cannot be used.
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        }
        if (m_interrupted.load(std::memory_order_acquire)) break;
        if (events.at(m_wake).occurred & Sock::RecvEvent) {
            std::array<char, 32> bytes;
            (void)m_wake->RecvFrom(bytes.data(), bytes.size(), nullptr, nullptr);
        }
        for (const auto& socket : sockets) {
            if (m_interrupted.load(std::memory_order_acquire)) break;
            if (events.at(socket).occurred & (Sock::RecvEvent | Sock::ErrorEvent)) receive(*socket);
        }
        if (m_interrupted.load(std::memory_order_acquire)) break;
        const auto now{std::chrono::steady_clock::now()};
        if (now >= deadline) {
            timer();
            // Coalesce missed ticks rather than starving sockets to catch up.
            deadline = std::chrono::steady_clock::now() + m_interval;
        }
    }
}

} // namespace fibre
