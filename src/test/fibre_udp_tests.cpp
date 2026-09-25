// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <fibre/udp_socket.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <future>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(fibre_udp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(interrupt_idle_wait)
{
    auto loop{fibre::ReadLoop::Create()};
    BOOST_REQUIRE(loop);
    auto task{std::async(std::launch::async, [&] { loop->Run({}, [](const auto&) {}, [] {}); })};
    BOOST_CHECK(task.wait_for(20ms) == std::future_status::timeout);
    loop->Interrupt();
    BOOST_CHECK(task.wait_for(2s) == std::future_status::ready);
    task.get();
}

BOOST_AUTO_TEST_CASE(timer_without_traffic)
{
    auto loop{fibre::ReadLoop::Create(10ms)};
    BOOST_REQUIRE(loop);
    unsigned ticks{0};
    auto task{std::async(std::launch::async, [&] {
        loop->Run({}, [](const auto&) {}, [&] { if (++ticks == 3) loop->Interrupt(); });
    })};
    const auto result{task.wait_for(2s)};
    loop->Interrupt();
    task.get();
    BOOST_CHECK(result == std::future_status::ready);
    BOOST_CHECK_EQUAL(ticks, 3U);
}

BOOST_AUTO_TEST_CASE(traffic_does_not_starve_timer)
{
    auto loop{fibre::ReadLoop::Create(10ms)};
    auto socket{fibre::DatagramSocket::Create(AF_INET)};
    BOOST_REQUIRE(loop);
    BOOST_REQUIRE(socket);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    BOOST_REQUIRE_EQUAL(socket->Bind(reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);
    socklen_t length{sizeof(address)};
    BOOST_REQUIRE_EQUAL(socket->GetSockName(reinterpret_cast<sockaddr*>(&address), &length), 0);
    const char byte{42};
    BOOST_REQUIRE_EQUAL(socket->SendTo(&byte, 1, reinterpret_cast<const sockaddr*>(&address), length), 1);
    unsigned reads{0}, ticks{0};
    auto task{std::async(std::launch::async, [&] {
        loop->Run({socket}, [&](const fibre::DatagramSocket& ready) {
            char received{};
            if (ready.RecvFrom(&received, 1, nullptr, nullptr) == 1 && received == byte) {
                ++reads;
                (void)ready.SendTo(&byte, 1, reinterpret_cast<const sockaddr*>(&address), length);
            }
        }, [&] { if (++ticks == 3) loop->Interrupt(); });
    })};
    const auto result{task.wait_for(2s)};
    loop->Interrupt();
    task.get();
    BOOST_CHECK(result == std::future_status::ready);
    BOOST_CHECK_EQUAL(ticks, 3U);
    BOOST_CHECK_GT(reads, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
