// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_FIBRE_UDP_SOCKET_H
#define BITCOIN_FIBRE_UDP_SOCKET_H

#include <util/sock.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace fibre {

/** Datagram operations kept in FIBRE rather than extending Core's stream API. */
class DatagramSocket final : public Sock
{
public:
    using Sock::operator=;
    explicit DatagramSocket(SOCKET socket) : Sock{socket} {}
    static std::shared_ptr<DatagramSocket> Create(int family);
    ssize_t SendTo(const void* data, size_t size, const sockaddr* address, socklen_t length) const;
    ssize_t RecvFrom(void* data, size_t size, sockaddr* address, socklen_t* length) const;
};

/** One receive callback per ready socket per iteration, with independent timer
 * deadlines. Socket ownership survives waits and shutdown until Run returns.
 * Interrupt uses a loopback datagram to wake the native wait; the timer deadline
 * also bounds the wait if that best-effort wakeup fails.
 */
class ReadLoop
{
public:
    static std::unique_ptr<ReadLoop> Create(std::chrono::milliseconds interval = std::chrono::milliseconds{500});
    void Run(const std::vector<std::shared_ptr<DatagramSocket>>& sockets,
             const std::function<void(const DatagramSocket&)>& receive,
             const std::function<void()>& timer);
    void Interrupt();

private:
    ReadLoop(std::shared_ptr<DatagramSocket> wake, const sockaddr_in& address, std::chrono::milliseconds interval)
        : m_wake{std::move(wake)}, m_address{address}, m_interval{interval} {}

    const std::shared_ptr<DatagramSocket> m_wake;
    const sockaddr_in m_address;
    const std::chrono::milliseconds m_interval;
    std::atomic_bool m_interrupted{false};
};

} // namespace fibre

#endif // BITCOIN_FIBRE_UDP_SOCKET_H
