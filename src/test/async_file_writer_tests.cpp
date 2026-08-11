// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging/async_file_writer.h>

#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/threadnames.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <future>
#include <functional>
#include <latch>
#include <semaphore>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

using BCLog::AsyncFileWriterEvent;
using BCLog::AsyncFileWriterEventKind;
using BCLog::AsyncFileWriterOperationKind;
using BCLog::EnqueueResult;

constexpr size_t MAX_PENDING_OPERATIONS{127};
constexpr auto WAIT_TIMEOUT{std::chrono::seconds{120}};
constexpr std::ptrdiff_t RELEASE_ALL_COUNT{512};
using Gate = std::counting_semaphore<1024>;

struct EventObservation {
    uint64_t sequence;
    FILE* file;
};

struct OperationObservation {
    AsyncFileWriterEventKind event_kind;
    uint64_t sequence;
    AsyncFileWriterOperationKind operation_kind;
    FILE* file;
    FILE* replacement_file;
};

template <typename T>
void RequireReady(std::future<T>& future)
{
    BOOST_REQUIRE(future.valid());
    BOOST_REQUIRE(future.wait_for(WAIT_TIMEOUT) == std::future_status::ready);
}

template <typename T>
void CheckNotReady(std::future<T>& future)
{
    BOOST_REQUIRE(future.valid());
    BOOST_CHECK(future.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
}

class TempFile
{
public:
    explicit TempFile(const fs::path& directory)
        : m_path{NewPath(directory)}, m_file{fsbridge::fopen(m_path, "w+b")}
    {
        BOOST_REQUIRE(m_file != nullptr);
        setbuf(m_file, nullptr);
    }

    ~TempFile()
    {
        if (m_file != nullptr && !m_worker_closed.load(std::memory_order_acquire)) fclose(m_file);
        std::error_code error;
        fs::remove(m_path, error);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    FILE* Get() const { return m_file; }

    void MarkWorkerClosed() noexcept
    {
        m_worker_closed.store(true, std::memory_order_release);
    }

    bool WasClosedByWorker() const noexcept
    {
        return m_worker_closed.load(std::memory_order_acquire);
    }

    std::string Read()
    {
        BOOST_REQUIRE(!WasClosedByWorker());
        BOOST_REQUIRE_EQUAL(fseek(m_file, 0, SEEK_SET), 0);
        std::string contents;
        std::array<char, 4096> buffer;
        while (const size_t size{fread(buffer.data(), 1, buffer.size(), m_file)}) {
            contents.append(buffer.data(), size);
        }
        BOOST_REQUIRE_EQUAL(ferror(m_file), 0);
        return contents;
    }

private:
    static fs::path NewPath(const fs::path& directory)
    {
        static std::atomic<uint64_t> next_id{0};
        const std::string filename{"async_file_writer_" + std::to_string(next_id.fetch_add(1, std::memory_order_relaxed)) + ".tmp"};
        return directory / fs::PathFromString(filename);
    }

    const fs::path m_path;
    FILE* const m_file;
    std::atomic<bool> m_worker_closed{false};
};

class TestHooks final : public BCLog::AsyncFileWriterTestHooks
{
public:
    using Handler = std::function<void(const AsyncFileWriterEvent&)>;

    explicit TestHooks(Handler handler) : m_handler{std::move(handler)} {}

    void OnEvent(const AsyncFileWriterEvent& event) noexcept override
    {
        m_handler(event);
    }

private:
    const Handler m_handler;
};

class WriterTestContext
{
public:
    WriterTestContext(const fs::path& temp_directory, TestHooks::Handler handler, std::function<void()> release_hooks = {}, std::function<void()> wait_tasks = {})
        : file{temp_directory}, hooks{std::move(handler)}, writer{&hooks}, m_release_hooks{std::move(release_hooks)}, m_wait_tasks{std::move(wait_tasks)}
    {
    }

    ~WriterTestContext()
    {
        if (m_release_hooks) m_release_hooks();
        writer.Stop();
        if (m_wait_tasks) m_wait_tasks();
    }

    void Start() { writer.Start(file.Get()); }
    void Start(FILE* start_file) { writer.Start(start_file); }

    TempFile file;
    TestHooks hooks;
    BCLog::AsyncFileWriter writer;

private:
    std::function<void()> m_release_hooks;
    std::function<void()> m_wait_tasks;
};

std::string NumberedLine(std::string_view prefix, size_t number)
{
    return std::string{prefix} + std::to_string(number) + "\n";
}

void RequireQueued(BCLog::AsyncFileWriter& writer, const std::string& line)
{
    BOOST_REQUIRE(writer.Write(line) == EnqueueResult::Queued);
}

struct AsyncFileWriterTestingSetup : BasicTestingSetup {
    AsyncFileWriterTestingSetup()
        : BasicTestingSetup{ChainType::REGTEST, {.extra_args = {"-nodebuglogfile", "-nodebug"}}}
    {
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(async_file_writer_tests, AsyncFileWriterTestingSetup)

BOOST_AUTO_TEST_CASE(fifo_write_order_and_worker_name)
{
    std::promise<std::string> thread_name_promise;
    auto thread_name_future{thread_name_promise.get_future()};
    std::atomic<bool> thread_name_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld &&
                !thread_name_recorded.exchange(true)) {
                thread_name_promise.set_value(util::ThreadGetInternalName());
            }
        }};

    context.Start();
    std::string expected;
    for (size_t i{0}; i < 64; ++i) {
        const std::string line{NumberedLine("fifo-", i)};
        expected += line;
        RequireQueued(context.writer, line);
    }

    context.writer.Flush();
    context.writer.Stop();
    RequireReady(thread_name_future);
    BOOST_CHECK_EQUAL(thread_name_future.get(), "logflush");
    BOOST_CHECK_EQUAL(context.file.Read(), expected);
}

BOOST_AUTO_TEST_CASE(common_case_is_asynchronous)
{
    constexpr size_t ADDITIONAL_LINES{16};
    std::vector<std::future<EnqueueResult>> producers;
    std::promise<EventObservation> file_operation_promise;
    auto file_operation_future{file_operation_promise.get_future()};
    Gate file_operation_release{0};
    std::latch producers_started{ADDITIONAL_LINES};
    std::atomic<bool> file_operation_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 1 && !file_operation_recorded.exchange(true)) {
                file_operation_promise.set_value({event.sequence, event.file});
                file_operation_release.acquire();
            }
        },
        [&] { file_operation_release.release(RELEASE_ALL_COUNT); },
        [&] {
            for (auto& producer : producers) {
                if (producer.valid()) producer.wait();
            }
        }};

    context.Start();
    std::string expected{NumberedLine("async-", 0)};
    RequireQueued(context.writer, expected);
    RequireReady(file_operation_future);
    const EventObservation operation{file_operation_future.get()};
    BOOST_CHECK_EQUAL(operation.sequence, 1);
    BOOST_CHECK(operation.file == context.file.Get());

    producers.reserve(ADDITIONAL_LINES);
    for (size_t i{1}; i <= ADDITIONAL_LINES; ++i) {
        const std::string line{NumberedLine("async-", i)};
        expected += line;
        producers.emplace_back(std::async(std::launch::async, [&, line] {
            producers_started.count_down();
            return context.writer.Write(line);
        }));
        RequireReady(producers.back());
        BOOST_CHECK(producers.back().get() == EnqueueResult::Queued);
    }
    producers_started.wait();

    file_operation_release.release();
    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK_EQUAL(context.file.Read(), expected);
}

BOOST_AUTO_TEST_CASE(exact_capacity_and_bounded_backpressure)
{
    std::future<EnqueueResult> overflow_producer;
    std::promise<EventObservation> file_operation_promise;
    auto file_operation_future{file_operation_promise.get_future()};
    std::promise<void> full_wait_promise;
    auto full_wait_future{full_wait_promise.get_future()};
    Gate file_operation_release{0};
    Gate full_wait_release{0};
    std::atomic<bool> file_operation_recorded{false};
    std::atomic<bool> full_wait_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 1 && !file_operation_recorded.exchange(true)) {
                file_operation_promise.set_value({event.sequence, event.file});
                file_operation_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                       !full_wait_recorded.exchange(true)) {
                full_wait_promise.set_value();
                full_wait_release.acquire();
            }
        },
        [&] {
            file_operation_release.release(RELEASE_ALL_COUNT);
            full_wait_release.release(RELEASE_ALL_COUNT);
        },
        [&] {
            if (overflow_producer.valid()) overflow_producer.wait();
        }};

    context.Start();
    std::string expected;
    for (size_t i{0}; i < MAX_PENDING_OPERATIONS; ++i) {
        const std::string line{NumberedLine("capacity-", i)};
        expected += line;
        RequireQueued(context.writer, line);
        if (i == 0) {
            RequireReady(file_operation_future);
            const EventObservation operation{file_operation_future.get()};
            BOOST_CHECK_EQUAL(operation.sequence, 1);
            BOOST_CHECK(operation.file == context.file.Get());
        }
    }

    const std::string overflow_line{NumberedLine("capacity-", MAX_PENDING_OPERATIONS)};
    expected += overflow_line;
    overflow_producer = std::async(std::launch::async, [&context, overflow_line] {
        return context.writer.Write(overflow_line);
    });
    RequireReady(full_wait_future);
    full_wait_future.get();
    CheckNotReady(overflow_producer);

    full_wait_release.release();
    file_operation_release.release();
    RequireReady(overflow_producer);
    BOOST_CHECK(overflow_producer.get() == EnqueueResult::Queued);

    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK_EQUAL(context.file.Read(), expected);
}

BOOST_AUTO_TEST_CASE(stale_empty_snapshot_regression)
{
    {
        std::future<bool> producer;
        std::promise<void> worker_prelock_promise;
        auto worker_prelock_future{worker_prelock_promise.get_future()};
        std::promise<void> full_wait_promise;
        auto full_wait_future{full_wait_promise.get_future()};
        Gate worker_prelock_release{0};
        Gate full_wait_release{0};
        std::atomic<bool> worker_prelock_recorded{false};
        std::atomic<bool> full_wait_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld &&
                    !worker_prelock_recorded.exchange(true)) {
                    worker_prelock_promise.set_value();
                    worker_prelock_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                           !full_wait_recorded.exchange(true)) {
                    full_wait_promise.set_value();
                    full_wait_release.acquire();
                }
            },
            [&] {
                worker_prelock_release.release(RELEASE_ALL_COUNT);
                full_wait_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (producer.valid()) producer.wait();
            }};

        context.Start();
        RequireReady(worker_prelock_future);
        worker_prelock_future.get();

        std::string expected;
        for (size_t i{0}; i <= MAX_PENDING_OPERATIONS; ++i) {
            expected += NumberedLine("stale-a-", i);
        }
        producer = std::async(std::launch::async, [&] {
            for (size_t i{0}; i <= MAX_PENDING_OPERATIONS; ++i) {
                if (context.writer.Write(NumberedLine("stale-a-", i)) != EnqueueResult::Queued) return false;
            }
            return true;
        });

        RequireReady(full_wait_future);
        full_wait_future.get();
        CheckNotReady(producer);
        worker_prelock_release.release();
        CheckNotReady(producer);
        full_wait_release.release();

        RequireReady(producer);
        BOOST_CHECK(producer.get());
        context.writer.Flush();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), expected);
    }

    {
        std::future<EnqueueResult> producer;
        std::promise<void> empty_wait_promise;
        auto empty_wait_future{empty_wait_promise.get_future()};
        Gate empty_wait_release{0};
        std::latch producer_started{1};
        std::atomic<bool> empty_wait_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeEmptyWaitLockHeld &&
                    !empty_wait_recorded.exchange(true)) {
                    empty_wait_promise.set_value();
                    empty_wait_release.acquire();
                }
            },
            [&] { empty_wait_release.release(RELEASE_ALL_COUNT); },
            [&] {
                if (producer.valid()) producer.wait();
            }};

        context.Start();
        RequireReady(empty_wait_future);
        empty_wait_future.get();
        producer = std::async(std::launch::async, [&] {
            producer_started.count_down();
            return context.writer.Write("stale-b\n");
        });
        producer_started.wait();
        CheckNotReady(producer);

        empty_wait_release.release();
        RequireReady(producer);
        BOOST_CHECK(producer.get() == EnqueueResult::Queued);
        context.writer.Flush();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), "stale-b\n");
    }
}

BOOST_AUTO_TEST_CASE(missed_full_transition_regression)
{
    std::future<EnqueueResult> overflow_producer;
    std::promise<void> file_operation_promise;
    auto file_operation_future{file_operation_promise.get_future()};
    std::promise<void> full_wait_promise;
    auto full_wait_future{full_wait_promise.get_future()};
    std::promise<void> after_file_promise;
    auto after_file_future{after_file_promise.get_future()};
    std::promise<void> slot_release_promise;
    auto slot_release_future{slot_release_promise.get_future()};
    Gate file_operation_release{0};
    Gate full_wait_release{0};
    Gate after_file_release{0};
    Gate slot_release_continue{0};
    std::atomic<bool> file_operation_recorded{false};
    std::atomic<bool> full_wait_recorded{false};
    std::atomic<bool> after_file_recorded{false};
    std::atomic<bool> slot_release_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 1 && !file_operation_recorded.exchange(true)) {
                file_operation_promise.set_value();
                file_operation_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                       !full_wait_recorded.exchange(true)) {
                full_wait_promise.set_value();
                full_wait_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock &&
                       event.sequence == 1 && !after_file_recorded.exchange(true)) {
                after_file_promise.set_value();
                after_file_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerAfterSlotReleaseLockHeld &&
                       event.sequence == 1 && !slot_release_recorded.exchange(true)) {
                slot_release_promise.set_value();
                slot_release_continue.acquire();
            }
        },
        [&] {
            file_operation_release.release(RELEASE_ALL_COUNT);
            full_wait_release.release(RELEASE_ALL_COUNT);
            after_file_release.release(RELEASE_ALL_COUNT);
            slot_release_continue.release(RELEASE_ALL_COUNT);
        },
        [&] {
            if (overflow_producer.valid()) overflow_producer.wait();
        }};

    context.Start();
    std::string expected;
    for (size_t i{0}; i < MAX_PENDING_OPERATIONS; ++i) {
        const std::string line{NumberedLine("full-transition-", i)};
        expected += line;
        RequireQueued(context.writer, line);
        if (i == 0) {
            RequireReady(file_operation_future);
            file_operation_future.get();
        }
    }

    const std::string overflow_line{NumberedLine("full-transition-", MAX_PENDING_OPERATIONS)};
    expected += overflow_line;
    overflow_producer = std::async(std::launch::async, [&context, overflow_line] {
        return context.writer.Write(overflow_line);
    });
    RequireReady(full_wait_future);
    full_wait_future.get();

    file_operation_release.release();
    RequireReady(after_file_future);
    after_file_future.get();
    after_file_release.release();
    CheckNotReady(slot_release_future);

    full_wait_release.release();
    RequireReady(slot_release_future);
    slot_release_future.get();
    CheckNotReady(overflow_producer);
    slot_release_continue.release();

    RequireReady(overflow_producer);
    BOOST_CHECK(overflow_producer.get() == EnqueueResult::Queued);
    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK_EQUAL(context.file.Read(), expected);
}

BOOST_AUTO_TEST_CASE(predicate_resilience)
{
    {
        std::future<void> first_boundary_probe;
        std::future<void> second_boundary_probe;
        std::promise<unsigned int> first_false_predicate_promise;
        auto first_false_predicate_future{first_false_predicate_promise.get_future()};
        std::promise<unsigned int> second_false_predicate_promise;
        auto second_false_predicate_future{second_false_predicate_promise.get_future()};
        std::promise<uint64_t> first_boundary_promise;
        auto first_boundary_future{first_boundary_promise.get_future()};
        std::promise<uint64_t> second_boundary_promise;
        auto second_boundary_future{second_boundary_promise.get_future()};
        std::promise<void> file_operation_promise;
        auto file_operation_future{file_operation_promise.get_future()};
        Gate first_false_predicate_release{0};
        Gate second_false_predicate_release{0};
        Gate first_boundary_release{0};
        Gate second_boundary_release{0};
        std::atomic<unsigned int> false_predicate_events{0};
        std::atomic<unsigned int> boundary_events{0};
        std::atomic<bool> expect_next_false_predicate{false};
        std::atomic<bool> file_operation_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerEmptyPredicateFalseLockHeld) {
                    const unsigned int ordinal{false_predicate_events.fetch_add(1) + 1};
                    if (ordinal == 1) {
                        first_false_predicate_promise.set_value(ordinal);
                        first_false_predicate_release.acquire();
                    } else if (expect_next_false_predicate.exchange(false)) {
                        second_false_predicate_promise.set_value(ordinal);
                        second_false_predicate_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld) {
                    const unsigned int index{boundary_events.fetch_add(1)};
                    if (index == 0) {
                        first_boundary_promise.set_value(event.sequence);
                        first_boundary_release.acquire();
                    } else if (index == 1) {
                        second_boundary_promise.set_value(event.sequence);
                        second_boundary_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                           !file_operation_recorded.exchange(true)) {
                    file_operation_promise.set_value();
                }
            },
            [&] {
                first_false_predicate_release.release(RELEASE_ALL_COUNT);
                second_false_predicate_release.release(RELEASE_ALL_COUNT);
                first_boundary_release.release(RELEASE_ALL_COUNT);
                second_boundary_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (first_boundary_probe.valid()) first_boundary_probe.wait();
                if (second_boundary_probe.valid()) second_boundary_probe.wait();
            }};

        context.Start();
        RequireReady(first_false_predicate_future);
        const unsigned int first_false_ordinal{first_false_predicate_future.get()};
        BOOST_CHECK_EQUAL(first_false_ordinal, 1);
        first_false_predicate_release.release();

        first_boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(first_boundary_future);
        BOOST_CHECK_EQUAL(first_boundary_future.get(), 0);
        expect_next_false_predicate.store(true);
        context.writer.WakeWaitersForTesting();
        first_boundary_release.release();
        RequireReady(first_boundary_probe);
        first_boundary_probe.get();

        RequireReady(second_false_predicate_future);
        BOOST_CHECK_GT(second_false_predicate_future.get(), first_false_ordinal);
        CheckNotReady(file_operation_future);
        second_false_predicate_release.release();

        second_boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(second_boundary_future);
        BOOST_CHECK_EQUAL(second_boundary_future.get(), 0);
        second_boundary_release.release();
        RequireReady(second_boundary_probe);
        second_boundary_probe.get();

        RequireQueued(context.writer, "predicate-empty\n");
        RequireReady(file_operation_future);
        file_operation_future.get();
        context.writer.Flush();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), "predicate-empty\n");
    }

    {
        std::future<EnqueueResult> overflow_producer;
        std::future<void> first_boundary_probe;
        std::future<void> second_boundary_probe;
        std::promise<void> file_operation_promise;
        auto file_operation_future{file_operation_promise.get_future()};
        std::promise<void> full_wait_promise;
        auto full_wait_future{full_wait_promise.get_future()};
        std::promise<unsigned int> first_false_predicate_promise;
        auto first_false_predicate_future{first_false_predicate_promise.get_future()};
        std::promise<unsigned int> second_false_predicate_promise;
        auto second_false_predicate_future{second_false_predicate_promise.get_future()};
        std::promise<uint64_t> first_boundary_promise;
        auto first_boundary_future{first_boundary_promise.get_future()};
        std::promise<uint64_t> second_boundary_promise;
        auto second_boundary_future{second_boundary_promise.get_future()};
        Gate file_operation_release{0};
        Gate full_wait_release{0};
        Gate first_false_predicate_release{0};
        Gate second_false_predicate_release{0};
        Gate first_boundary_release{0};
        Gate second_boundary_release{0};
        std::atomic<bool> file_operation_recorded{false};
        std::atomic<bool> full_wait_recorded{false};
        std::atomic<unsigned int> false_predicate_events{0};
        std::atomic<unsigned int> boundary_events{0};
        std::atomic<bool> expect_next_false_predicate{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                    event.sequence == 1 && !file_operation_recorded.exchange(true)) {
                    file_operation_promise.set_value();
                    file_operation_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                           !full_wait_recorded.exchange(true)) {
                    full_wait_promise.set_value();
                    full_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::ProducerFullPredicateFalseLockHeld) {
                    const unsigned int ordinal{false_predicate_events.fetch_add(1) + 1};
                    if (ordinal == 1) {
                        first_false_predicate_promise.set_value(ordinal);
                        first_false_predicate_release.acquire();
                    } else if (expect_next_false_predicate.exchange(false)) {
                        second_false_predicate_promise.set_value(ordinal);
                        second_false_predicate_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld) {
                    const unsigned int index{boundary_events.fetch_add(1)};
                    if (index == 0) {
                        first_boundary_promise.set_value(event.sequence);
                        first_boundary_release.acquire();
                    } else if (index == 1) {
                        second_boundary_promise.set_value(event.sequence);
                        second_boundary_release.acquire();
                    }
                }
            },
            [&] {
                file_operation_release.release(RELEASE_ALL_COUNT);
                full_wait_release.release(RELEASE_ALL_COUNT);
                first_false_predicate_release.release(RELEASE_ALL_COUNT);
                second_false_predicate_release.release(RELEASE_ALL_COUNT);
                first_boundary_release.release(RELEASE_ALL_COUNT);
                second_boundary_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (overflow_producer.valid()) overflow_producer.wait();
                if (first_boundary_probe.valid()) first_boundary_probe.wait();
                if (second_boundary_probe.valid()) second_boundary_probe.wait();
            }};

        context.Start();
        std::string expected;
        for (size_t i{0}; i < MAX_PENDING_OPERATIONS; ++i) {
            const std::string line{NumberedLine("predicate-full-", i)};
            expected += line;
            RequireQueued(context.writer, line);
            if (i == 0) {
                RequireReady(file_operation_future);
                file_operation_future.get();
            }
        }

        const std::string overflow_line{NumberedLine("predicate-full-", MAX_PENDING_OPERATIONS)};
        expected += overflow_line;
        overflow_producer = std::async(std::launch::async, [&context, overflow_line] {
            return context.writer.Write(overflow_line);
        });
        RequireReady(full_wait_future);
        full_wait_future.get();
        full_wait_release.release();

        RequireReady(first_false_predicate_future);
        const unsigned int first_false_ordinal{first_false_predicate_future.get()};
        BOOST_CHECK_GT(first_false_ordinal, 0U);
        first_false_predicate_release.release();

        first_boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(first_boundary_future);
        BOOST_CHECK_EQUAL(first_boundary_future.get(), MAX_PENDING_OPERATIONS);
        expect_next_false_predicate.store(true);
        context.writer.WakeWaitersForTesting();
        first_boundary_release.release();

        RequireReady(second_false_predicate_future);
        BOOST_CHECK_GT(second_false_predicate_future.get(), first_false_ordinal);
        CheckNotReady(overflow_producer);
        second_false_predicate_release.release();

        second_boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(second_boundary_future);
        BOOST_CHECK_EQUAL(second_boundary_future.get(), MAX_PENDING_OPERATIONS);
        second_boundary_release.release();
        CheckNotReady(overflow_producer);

        file_operation_release.release();
        RequireReady(overflow_producer);
        BOOST_CHECK(overflow_producer.get() == EnqueueResult::Queued);
        RequireReady(first_boundary_probe);
        first_boundary_probe.get();
        RequireReady(second_boundary_probe);
        second_boundary_probe.get();
        context.writer.Flush();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), expected);
    }
}

BOOST_AUTO_TEST_CASE(exact_flush_boundary)
{
    {
        std::future<void> flush;
        std::future<EnqueueResult> producer_c;
        std::promise<void> operation_a_promise;
        auto operation_a_future{operation_a_promise.get_future()};
        std::promise<uint64_t> boundary_promise;
        auto boundary_future{boundary_promise.get_future()};
        std::promise<void> operation_c_promise;
        auto operation_c_future{operation_c_promise.get_future()};
        Gate operation_a_release{0};
        Gate boundary_release{0};
        Gate operation_c_release{0};
        std::latch producer_c_started{1};
        std::atomic<bool> operation_a_recorded{false};
        std::atomic<bool> boundary_recorded{false};
        std::atomic<bool> operation_c_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                    event.sequence == 1 && !operation_a_recorded.exchange(true)) {
                    operation_a_promise.set_value();
                    operation_a_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld &&
                           !boundary_recorded.exchange(true)) {
                    boundary_promise.set_value(event.sequence);
                    boundary_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                           event.sequence == 3 && !operation_c_recorded.exchange(true)) {
                    operation_c_promise.set_value();
                    operation_c_release.acquire();
                }
            },
            [&] {
                operation_a_release.release(RELEASE_ALL_COUNT);
                boundary_release.release(RELEASE_ALL_COUNT);
                operation_c_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (flush.valid()) flush.wait();
                if (producer_c.valid()) producer_c.wait();
            }};

        context.Start();
        RequireQueued(context.writer, "A\n");
        RequireReady(operation_a_future);
        operation_a_future.get();
        RequireQueued(context.writer, "B\n");

        flush = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_future);
        BOOST_CHECK_EQUAL(boundary_future.get(), 2);

        producer_c = std::async(std::launch::async, [&] {
            producer_c_started.count_down();
            return context.writer.Write("C\n");
        });
        producer_c_started.wait();
        CheckNotReady(producer_c);
        boundary_release.release();
        RequireReady(producer_c);
        BOOST_CHECK(producer_c.get() == EnqueueResult::Queued);

        operation_a_release.release();
        RequireReady(operation_c_future);
        operation_c_future.get();
        RequireReady(flush);
        flush.get();
        operation_c_release.release();

        context.writer.Flush();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), "A\nB\nC\n");
    }

    {
        std::future<void> flush_f1;
        std::future<void> flush_f2;
        std::promise<void> operation_a_promise;
        auto operation_a_future{operation_a_promise.get_future()};
        std::promise<uint64_t> boundary_f1_promise;
        auto boundary_f1_future{boundary_f1_promise.get_future()};
        std::promise<uint64_t> boundary_f2_promise;
        auto boundary_f2_future{boundary_f2_promise.get_future()};
        std::promise<void> operation_b_promise;
        auto operation_b_future{operation_b_promise.get_future()};
        Gate operation_a_release{0};
        Gate boundary_f1_release{0};
        Gate boundary_f2_release{0};
        Gate operation_b_release{0};
        std::atomic<bool> operation_a_recorded{false};
        std::atomic<unsigned int> flush_events{0};
        std::atomic<bool> operation_b_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                    event.sequence == 1 && !operation_a_recorded.exchange(true)) {
                    operation_a_promise.set_value();
                    operation_a_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld) {
                    const unsigned int flush_index{flush_events.fetch_add(1)};
                    if (flush_index == 0) {
                        boundary_f1_promise.set_value(event.sequence);
                        boundary_f1_release.acquire();
                    } else if (flush_index == 1) {
                        boundary_f2_promise.set_value(event.sequence);
                        boundary_f2_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                           event.sequence == 2 && !operation_b_recorded.exchange(true)) {
                    operation_b_promise.set_value();
                    operation_b_release.acquire();
                }
            },
            [&] {
                operation_a_release.release(RELEASE_ALL_COUNT);
                boundary_f1_release.release(RELEASE_ALL_COUNT);
                boundary_f2_release.release(RELEASE_ALL_COUNT);
                operation_b_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (flush_f1.valid()) flush_f1.wait();
                if (flush_f2.valid()) flush_f2.wait();
            }};

        context.Start();
        RequireQueued(context.writer, "A\n");
        RequireReady(operation_a_future);
        operation_a_future.get();

        flush_f1 = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_f1_future);
        BOOST_CHECK_EQUAL(boundary_f1_future.get(), 1);
        boundary_f1_release.release();
        RequireQueued(context.writer, "B\n");

        flush_f2 = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_f2_future);
        BOOST_CHECK_EQUAL(boundary_f2_future.get(), 2);
        boundary_f2_release.release();

        operation_a_release.release();
        RequireReady(operation_b_future);
        operation_b_future.get();
        RequireReady(flush_f1);
        flush_f1.get();
        CheckNotReady(flush_f2);
        operation_b_release.release();

        RequireReady(flush_f2);
        flush_f2.get();
        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), "A\nB\n");
    }
}

BOOST_AUTO_TEST_CASE(wait_predicate_contract)
{
    constexpr uint64_t RUN_A{41};
    constexpr uint64_t RUN_B{42};
    constexpr std::size_t CAPACITY{127};

    BOOST_CHECK(!BCLog::detail::AsyncFileWriterRunChanged(RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterRunChanged(RUN_A, RUN_B));

    BOOST_CHECK(!BCLog::detail::AsyncFileWriterLifecycleWaitReady(false, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterLifecycleWaitReady(true, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterLifecycleWaitReady(false, RUN_A, RUN_B));

    BOOST_CHECK(!BCLog::detail::AsyncFileWriterNotFullWaitReady(true, CAPACITY, CAPACITY, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterNotFullWaitReady(true, CAPACITY - 1, CAPACITY, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterNotFullWaitReady(false, CAPACITY, CAPACITY, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterNotFullWaitReady(true, CAPACITY, CAPACITY, RUN_A, RUN_B));

    BOOST_CHECK(!BCLog::detail::AsyncFileWriterFlushWaitReady(126, 127, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterFlushWaitReady(127, 127, RUN_A, RUN_A));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterFlushWaitReady(0, 127, RUN_A, RUN_B));

    BOOST_CHECK(!BCLog::detail::AsyncFileWriterWorkerWaitReady(0, false));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterWorkerWaitReady(1, false));
    BOOST_CHECK(BCLog::detail::AsyncFileWriterWorkerWaitReady(0, true));
}

BOOST_AUTO_TEST_CASE(restart_generation_isolates_prior_run_waiters)
{
    {
        TempFile run_b_file{m_path_root};
        std::future<void> stop_s1;
        std::future<void> stop_s2;
        std::future<EnqueueResult> write_w;
        std::future<void> boundary_probe;
        std::promise<void> worker_prelock_promise;
        auto worker_prelock_future{worker_prelock_promise.get_future()};
        std::promise<void> stop_prejoin_promise;
        auto stop_prejoin_future{stop_prejoin_promise.get_future()};
        std::promise<void> stop_wait_promise;
        auto stop_wait_future{stop_wait_promise.get_future()};
        std::promise<void> write_wait_promise;
        auto write_wait_future{write_wait_promise.get_future()};
        std::promise<uint64_t> boundary_promise;
        auto boundary_future{boundary_promise.get_future()};
        std::promise<void> stop_final_promise;
        auto stop_final_future{stop_final_promise.get_future()};
        Gate worker_prelock_release{0};
        Gate stop_prejoin_release{0};
        Gate stop_wait_release{0};
        Gate write_wait_release{0};
        Gate boundary_release{0};
        Gate stop_final_release{0};
        std::atomic<bool> worker_prelock_recorded{false};
        std::atomic<bool> stop_prejoin_recorded{false};
        std::atomic<bool> stop_wait_recorded{false};
        std::atomic<bool> write_wait_recorded{false};
        std::atomic<bool> boundary_recorded{false};
        std::atomic<bool> stop_final_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld &&
                    !worker_prelock_recorded.exchange(true)) {
                    worker_prelock_promise.set_value();
                    worker_prelock_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld &&
                           !stop_prejoin_recorded.exchange(true)) {
                    stop_prejoin_promise.set_value();
                    stop_prejoin_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopBeforeDrainingWaitLockHeld &&
                           !stop_wait_recorded.exchange(true)) {
                    stop_wait_promise.set_value();
                    stop_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::WriteBeforeDrainingWaitLockHeld &&
                           !write_wait_recorded.exchange(true)) {
                    write_wait_promise.set_value();
                    write_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld &&
                           !boundary_recorded.exchange(true)) {
                    boundary_promise.set_value(event.sequence);
                    boundary_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopAfterStateStoppedBeforeProgressNotifyLockNotHeld &&
                           !stop_final_recorded.exchange(true)) {
                    stop_final_promise.set_value();
                    stop_final_release.acquire();
                }
            },
            [&] {
                worker_prelock_release.release(RELEASE_ALL_COUNT);
                stop_prejoin_release.release(RELEASE_ALL_COUNT);
                stop_wait_release.release(RELEASE_ALL_COUNT);
                write_wait_release.release(RELEASE_ALL_COUNT);
                boundary_release.release(RELEASE_ALL_COUNT);
                stop_final_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (stop_s1.valid()) stop_s1.wait();
                if (stop_s2.valid()) stop_s2.wait();
                if (write_w.valid()) write_w.wait();
                if (boundary_probe.valid()) boundary_probe.wait();
            }};

        context.Start();
        RequireReady(worker_prelock_future);
        worker_prelock_future.get();

        stop_s1 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        RequireReady(stop_prejoin_future);
        stop_prejoin_future.get();

        stop_s2 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        RequireReady(stop_wait_future);
        stop_wait_future.get();
        stop_wait_release.release();

        const std::string run_a_only_line{"empty-run-a-only\n"};
        write_w = std::async(std::launch::async, [&context, run_a_only_line] {
            return context.writer.Write(run_a_only_line);
        });
        RequireReady(write_wait_future);
        write_wait_future.get();
        write_wait_release.release();

        boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_future);
        BOOST_CHECK_EQUAL(boundary_future.get(), 0);
        boundary_release.release();
        RequireReady(boundary_probe);
        boundary_probe.get();

        stop_prejoin_release.release();
        worker_prelock_release.release();
        RequireReady(stop_final_future);
        stop_final_future.get();

        context.writer.Start(run_b_file.Get());
        stop_final_release.release();

        RequireReady(stop_s1);
        stop_s1.get();
        RequireReady(stop_s2);
        stop_s2.get();
        RequireReady(write_w);
        BOOST_CHECK(write_w.get() == EnqueueResult::Stopped);

        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), "");
        BOOST_CHECK_EQUAL(run_b_file.Read(), "");
    }

    {
        TempFile run_b_file{m_path_root};
        std::future<void> flush_f;
        std::future<void> flush_probe;
        std::future<EnqueueResult> producer_p;
        std::future<void> stop_s1;
        std::future<void> stop_s2;
        std::promise<void> operation_one_promise;
        auto operation_one_future{operation_one_promise.get_future()};
        std::promise<uint64_t> boundary_f_promise;
        auto boundary_f_future{boundary_f_promise.get_future()};
        std::promise<void> full_wait_promise;
        auto full_wait_future{full_wait_promise.get_future()};
        std::promise<void> stop_prejoin_promise;
        auto stop_prejoin_future{stop_prejoin_promise.get_future()};
        std::promise<void> write_wait_promise;
        auto write_wait_future{write_wait_promise.get_future()};
        std::promise<void> stop_wait_promise;
        auto stop_wait_future{stop_wait_promise.get_future()};
        std::promise<uint64_t> boundary_probe_promise;
        auto boundary_probe_future{boundary_probe_promise.get_future()};
        std::promise<void> stop_final_promise;
        auto stop_final_future{stop_final_promise.get_future()};
        Gate operation_one_release{0};
        Gate boundary_f_release{0};
        Gate full_wait_release{0};
        Gate stop_prejoin_release{0};
        Gate write_wait_release{0};
        Gate stop_wait_release{0};
        Gate boundary_probe_release{0};
        Gate stop_final_release{0};
        std::atomic<bool> operation_one_recorded{false};
        std::atomic<unsigned int> boundary_events{0};
        std::atomic<bool> full_wait_recorded{false};
        std::atomic<bool> stop_prejoin_recorded{false};
        std::atomic<bool> write_wait_recorded{false};
        std::atomic<bool> stop_wait_recorded{false};
        std::atomic<bool> stop_final_recorded{false};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                    event.sequence == 1 && !operation_one_recorded.exchange(true)) {
                    operation_one_promise.set_value();
                    operation_one_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld) {
                    const unsigned int index{boundary_events.fetch_add(1)};
                    if (index == 0) {
                        boundary_f_promise.set_value(event.sequence);
                        boundary_f_release.acquire();
                    } else if (index == 1) {
                        boundary_probe_promise.set_value(event.sequence);
                        boundary_probe_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                           !full_wait_recorded.exchange(true)) {
                    full_wait_promise.set_value();
                    full_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld &&
                           !stop_prejoin_recorded.exchange(true)) {
                    stop_prejoin_promise.set_value();
                    stop_prejoin_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::WriteBeforeDrainingWaitLockHeld &&
                           !write_wait_recorded.exchange(true)) {
                    write_wait_promise.set_value();
                    write_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopBeforeDrainingWaitLockHeld &&
                           !stop_wait_recorded.exchange(true)) {
                    stop_wait_promise.set_value();
                    stop_wait_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopAfterStateStoppedBeforeProgressNotifyLockNotHeld &&
                           !stop_final_recorded.exchange(true)) {
                    stop_final_promise.set_value();
                    stop_final_release.acquire();
                }
            },
            [&] {
                operation_one_release.release(RELEASE_ALL_COUNT);
                boundary_f_release.release(RELEASE_ALL_COUNT);
                full_wait_release.release(RELEASE_ALL_COUNT);
                stop_prejoin_release.release(RELEASE_ALL_COUNT);
                write_wait_release.release(RELEASE_ALL_COUNT);
                stop_wait_release.release(RELEASE_ALL_COUNT);
                boundary_probe_release.release(RELEASE_ALL_COUNT);
                stop_final_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (flush_f.valid()) flush_f.wait();
                if (flush_probe.valid()) flush_probe.wait();
                if (producer_p.valid()) producer_p.wait();
                if (stop_s1.valid()) stop_s1.wait();
                if (stop_s2.valid()) stop_s2.wait();
            }};

        context.Start();
        std::string expected;
        for (size_t i{0}; i < MAX_PENDING_OPERATIONS; ++i) {
            const std::string line{NumberedLine("generation-run-a-", i)};
            expected += line;
            RequireQueued(context.writer, line);
            if (i == 0) {
                RequireReady(operation_one_future);
                operation_one_future.get();
            }
        }

        flush_f = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_f_future);
        BOOST_CHECK_EQUAL(boundary_f_future.get(), MAX_PENDING_OPERATIONS);
        boundary_f_release.release();

        const std::string overflow_line{"generation-run-a-overflow\n"};
        producer_p = std::async(std::launch::async, [&context, overflow_line] {
            return context.writer.Write(overflow_line);
        });
        RequireReady(full_wait_future);
        full_wait_future.get();

        stop_s1 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        full_wait_release.release();
        RequireReady(stop_prejoin_future);
        stop_prejoin_future.get();

        RequireReady(write_wait_future);
        write_wait_future.get();
        write_wait_release.release();

        stop_s2 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        RequireReady(stop_wait_future);
        stop_wait_future.get();
        stop_wait_release.release();

        flush_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
        RequireReady(boundary_probe_future);
        BOOST_CHECK_EQUAL(boundary_probe_future.get(), MAX_PENDING_OPERATIONS);
        boundary_probe_release.release();

        stop_prejoin_release.release();
        operation_one_release.release();
        RequireReady(stop_final_future);
        stop_final_future.get();

        context.writer.Start(run_b_file.Get());
        stop_final_release.release();

        RequireReady(flush_f);
        flush_f.get();
        RequireReady(flush_probe);
        flush_probe.get();
        RequireReady(producer_p);
        BOOST_CHECK(producer_p.get() == EnqueueResult::Stopped);
        RequireReady(stop_s2);
        stop_s2.get();
        RequireReady(stop_s1);
        stop_s1.get();

        context.writer.Stop();
        BOOST_CHECK_EQUAL(context.file.Read(), expected);
        BOOST_CHECK_EQUAL(run_b_file.Read(), "");
    }
}

BOOST_AUTO_TEST_CASE(stop_drains_accepted_writes)
{
    constexpr size_t LINE_COUNT{16};
    std::future<void> stop;
    std::promise<void> operation_one_promise;
    auto operation_one_future{operation_one_promise.get_future()};
    std::promise<void> stop_prejoin_promise;
    auto stop_prejoin_future{stop_prejoin_promise.get_future()};
    Gate operation_one_release{0};
    std::atomic<bool> operation_one_recorded{false};
    std::atomic<bool> stop_prejoin_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 1 && !operation_one_recorded.exchange(true)) {
                operation_one_promise.set_value();
                operation_one_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld &&
                       !stop_prejoin_recorded.exchange(true)) {
                stop_prejoin_promise.set_value();
            }
        },
        [&] { operation_one_release.release(RELEASE_ALL_COUNT); },
        [&] {
            if (stop.valid()) stop.wait();
        }};

    context.Start();
    std::string expected;
    for (size_t i{0}; i < LINE_COUNT; ++i) {
        const std::string line{NumberedLine("stop-drain-", i)};
        expected += line;
        RequireQueued(context.writer, line);
        if (i == 0) {
            RequireReady(operation_one_future);
            operation_one_future.get();
        }
    }

    stop = std::async(std::launch::async, [&] { context.writer.Stop(); });
    RequireReady(stop_prejoin_future);
    stop_prejoin_future.get();
    CheckNotReady(stop);

    operation_one_release.release();
    RequireReady(stop);
    stop.get();
    BOOST_CHECK_EQUAL(context.file.Read(), expected);
}

BOOST_AUTO_TEST_CASE(blocked_producer_returns_stopped_during_stop)
{
    TempFile run_b_file{m_path_root};
    std::future<EnqueueResult> overflow_producer;
    std::future<void> boundary_probe;
    std::future<void> stop;
    std::promise<void> operation_one_promise;
    auto operation_one_future{operation_one_promise.get_future()};
    std::promise<void> full_wait_promise;
    auto full_wait_future{full_wait_promise.get_future()};
    std::promise<void> false_predicate_promise;
    auto false_predicate_future{false_predicate_promise.get_future()};
    std::promise<uint64_t> boundary_promise;
    auto boundary_future{boundary_promise.get_future()};
    std::promise<void> draining_wait_promise;
    auto draining_wait_future{draining_wait_promise.get_future()};
    std::promise<void> stop_prejoin_promise;
    auto stop_prejoin_future{stop_prejoin_promise.get_future()};
    Gate operation_one_release{0};
    Gate full_wait_release{0};
    Gate boundary_release{0};
    Gate draining_wait_release{0};
    std::atomic<bool> operation_one_recorded{false};
    std::atomic<bool> full_wait_recorded{false};
    std::atomic<bool> false_predicate_recorded{false};
    std::atomic<bool> boundary_recorded{false};
    std::atomic<bool> draining_wait_recorded{false};
    std::atomic<bool> stop_prejoin_recorded{false};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 1 && !operation_one_recorded.exchange(true)) {
                operation_one_promise.set_value();
                operation_one_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld &&
                       !full_wait_recorded.exchange(true)) {
                full_wait_promise.set_value();
                full_wait_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::ProducerFullPredicateFalseLockHeld &&
                       !false_predicate_recorded.exchange(true)) {
                false_predicate_promise.set_value();
            } else if (event.kind == AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld &&
                       !boundary_recorded.exchange(true)) {
                boundary_promise.set_value(event.sequence);
                boundary_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WriteBeforeDrainingWaitLockHeld &&
                       !draining_wait_recorded.exchange(true)) {
                draining_wait_promise.set_value();
                draining_wait_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld &&
                       !stop_prejoin_recorded.exchange(true)) {
                stop_prejoin_promise.set_value();
            }
        },
        [&] {
            operation_one_release.release(RELEASE_ALL_COUNT);
            full_wait_release.release(RELEASE_ALL_COUNT);
            boundary_release.release(RELEASE_ALL_COUNT);
            draining_wait_release.release(RELEASE_ALL_COUNT);
        },
        [&] {
            if (overflow_producer.valid()) overflow_producer.wait();
            if (boundary_probe.valid()) boundary_probe.wait();
            if (stop.valid()) stop.wait();
        }};

    context.Start();
    std::string expected;
    for (size_t i{0}; i < MAX_PENDING_OPERATIONS; ++i) {
        const std::string line{NumberedLine("stop-full-", i)};
        expected += line;
        RequireQueued(context.writer, line);
        if (i == 0) {
            RequireReady(operation_one_future);
            operation_one_future.get();
        }
    }

    const std::string overflow_line{"stop-full-overflow\n"};
    overflow_producer = std::async(std::launch::async, [&context, overflow_line] {
        return context.writer.Write(overflow_line);
    });
    RequireReady(full_wait_future);
    full_wait_future.get();
    full_wait_release.release();
    RequireReady(false_predicate_future);
    false_predicate_future.get();

    boundary_probe = std::async(std::launch::async, [&] { context.writer.Flush(); });
    RequireReady(boundary_future);
    BOOST_CHECK_EQUAL(boundary_future.get(), MAX_PENDING_OPERATIONS);
    boundary_release.release();

    stop = std::async(std::launch::async, [&] { context.writer.Stop(); });
    RequireReady(stop_prejoin_future);
    stop_prejoin_future.get();
    RequireReady(draining_wait_future);
    draining_wait_future.get();
    CheckNotReady(overflow_producer);
    CheckNotReady(stop);
    draining_wait_release.release();

    operation_one_release.release();
    RequireReady(stop);
    stop.get();
    RequireReady(overflow_producer);
    BOOST_CHECK(overflow_producer.get() == EnqueueResult::Stopped);
    RequireReady(boundary_probe);
    boundary_probe.get();
    BOOST_CHECK_EQUAL(context.file.Read(), expected);

    context.writer.Start(run_b_file.Get());
    RequireQueued(context.writer, "new-run-marker\n");
    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK_EQUAL(run_b_file.Read(), "new-run-marker\n");
}

BOOST_AUTO_TEST_CASE(stop_is_idempotent_and_single_join_owner)
{
    {
        TempFile file{m_path_root};
        BCLog::AsyncFileWriter writer;
        writer.Stop();
        writer.Start(file.Get());
        writer.Stop();
    }

    {
        TempFile file{m_path_root};
        BCLog::AsyncFileWriter writer;
        writer.Start(file.Get());
        writer.Stop();
        writer.Stop();
        writer.Start(file.Get());
        writer.Stop();
        BOOST_CHECK_EQUAL(file.Read(), "");
    }

    {
        std::future<void> stop_s1;
        std::future<void> stop_s2;
        std::promise<void> worker_prelock_promise;
        auto worker_prelock_future{worker_prelock_promise.get_future()};
        std::promise<void> join_owner_promise;
        auto join_owner_future{join_owner_promise.get_future()};
        std::promise<void> draining_wait_promise;
        auto draining_wait_future{draining_wait_promise.get_future()};
        Gate worker_prelock_release{0};
        Gate join_owner_release{0};
        Gate draining_wait_release{0};
        std::atomic<bool> worker_prelock_recorded{false};
        std::atomic<unsigned int> join_owner_events{0};
        std::atomic<unsigned int> draining_wait_events{0};

        WriterTestContext context{
            m_path_root,
            [&](const AsyncFileWriterEvent& event) noexcept {
                if (event.kind == AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld &&
                    !worker_prelock_recorded.exchange(true)) {
                    worker_prelock_promise.set_value();
                    worker_prelock_release.acquire();
                } else if (event.kind == AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld) {
                    const unsigned int ordinal{join_owner_events.fetch_add(1) + 1};
                    if (ordinal == 1) {
                        join_owner_promise.set_value();
                        join_owner_release.acquire();
                    }
                } else if (event.kind == AsyncFileWriterEventKind::StopBeforeDrainingWaitLockHeld) {
                    const unsigned int ordinal{draining_wait_events.fetch_add(1) + 1};
                    if (ordinal == 1) {
                        draining_wait_promise.set_value();
                        draining_wait_release.acquire();
                    }
                }
            },
            [&] {
                worker_prelock_release.release(RELEASE_ALL_COUNT);
                join_owner_release.release(RELEASE_ALL_COUNT);
                draining_wait_release.release(RELEASE_ALL_COUNT);
            },
            [&] {
                if (stop_s1.valid()) stop_s1.wait();
                if (stop_s2.valid()) stop_s2.wait();
            }};

        context.Start();
        RequireReady(worker_prelock_future);
        worker_prelock_future.get();

        stop_s1 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        RequireReady(join_owner_future);
        join_owner_future.get();
        stop_s2 = std::async(std::launch::async, [&] { context.writer.Stop(); });
        RequireReady(draining_wait_future);
        draining_wait_future.get();
        BOOST_CHECK_EQUAL(join_owner_events.load(), 1U);
        BOOST_CHECK_EQUAL(draining_wait_events.load(), 1U);
        CheckNotReady(stop_s1);
        CheckNotReady(stop_s2);

        draining_wait_release.release();
        join_owner_release.release();
        CheckNotReady(stop_s1);
        CheckNotReady(stop_s2);
        worker_prelock_release.release();

        RequireReady(stop_s1);
        stop_s1.get();
        RequireReady(stop_s2);
        stop_s2.get();
        BOOST_CHECK_EQUAL(join_owner_events.load(), 1U);
        BOOST_CHECK_EQUAL(draining_wait_events.load(), 1U);
    }

    {
        TempFile file{m_path_root};
        {
            BCLog::AsyncFileWriter writer;
            writer.Start(file.Get());
            writer.Stop();
        }
        BOOST_CHECK_EQUAL(file.Read(), "");
    }
}

BOOST_AUTO_TEST_CASE(sequential_restart_uses_distinct_streams)
{
    TempFile file_a{m_path_root};
    TempFile file_b{m_path_root};
    BOOST_REQUIRE(file_a.Get() != file_b.Get());
    BCLog::AsyncFileWriter writer;

    writer.Start(file_a.Get());
    RequireQueued(writer, "run-a\n");
    writer.Flush();
    writer.Stop();
    BOOST_CHECK_EQUAL(file_a.Read(), "run-a\n");

    writer.Start(file_b.Get());
    RequireQueued(writer, "run-b\n");
    writer.Flush();
    writer.Stop();
    BOOST_CHECK_EQUAL(file_a.Read(), "run-a\n");
    BOOST_CHECK_EQUAL(file_b.Read(), "run-b\n");
}

BOOST_AUTO_TEST_CASE(single_reopen_is_ordered_and_closes_old_stream)
{
    TempFile file_a{m_path_root};
    TempFile file_b{m_path_root};
    BOOST_REQUIRE(file_a.Get() != file_b.Get());
    std::promise<void> before_reopen_promise;
    auto before_reopen_future{before_reopen_promise.get_future()};
    std::promise<void> after_reopen_promise;
    auto after_reopen_future{after_reopen_promise.get_future()};
    Gate before_reopen_release{0};
    std::atomic<bool> before_reopen_recorded{false};
    std::atomic<bool> after_reopen_recorded{false};
    std::array<OperationObservation, 10> operation_events{};
    std::atomic<size_t> operation_event_count{0};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld ||
                event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock) {
                const size_t index{operation_event_count.fetch_add(1)};
                if (index < operation_events.size()) {
                    operation_events[index] = {
                        event.kind,
                        event.sequence,
                        event.operation_kind,
                        event.file,
                        event.replacement_file,
                    };
                }
            }
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                event.sequence == 3 &&
                event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                !before_reopen_recorded.exchange(true)) {
                before_reopen_promise.set_value();
                before_reopen_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock &&
                       event.sequence == 3 &&
                       event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                       !after_reopen_recorded.exchange(true)) {
                file_a.MarkWorkerClosed();
                after_reopen_promise.set_value();
            }
        },
        [&] { before_reopen_release.release(RELEASE_ALL_COUNT); }};

    context.Start(file_a.Get());
    RequireQueued(context.writer, "A1\n");
    RequireQueued(context.writer, "A2\n");
    BOOST_REQUIRE(context.writer.Reopen(file_b.Get()) == EnqueueResult::Queued);
    RequireQueued(context.writer, "B1\n");
    RequireQueued(context.writer, "B2\n");

    RequireReady(before_reopen_future);
    before_reopen_future.get();
    BOOST_CHECK_EQUAL(file_a.Read(), "A1\nA2\n");
    before_reopen_release.release();
    RequireReady(after_reopen_future);
    after_reopen_future.get();

    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK(file_a.WasClosedByWorker());
    BOOST_CHECK_EQUAL(file_b.Read(), "B1\nB2\n");
    BOOST_CHECK(!file_b.WasClosedByWorker());
    BOOST_REQUIRE_EQUAL(operation_event_count.load(), operation_events.size());

    const auto check_event = [&](size_t index,
                                 AsyncFileWriterEventKind event_kind,
                                 uint64_t sequence,
                                 AsyncFileWriterOperationKind operation_kind,
                                 FILE* file,
                                 FILE* replacement_file) {
        const OperationObservation& event{operation_events[index]};
        BOOST_CHECK(event.event_kind == event_kind);
        BOOST_CHECK_EQUAL(event.sequence, sequence);
        BOOST_CHECK(event.operation_kind == operation_kind);
        BOOST_CHECK(event.file == file);
        BOOST_CHECK(event.replacement_file == replacement_file);
    };
    check_event(0, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 1, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(1, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 1, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(2, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 2, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(3, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 2, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(4, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 3, AsyncFileWriterOperationKind::ReopenFile, file_a.Get(), file_b.Get());
    check_event(5, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 3, AsyncFileWriterOperationKind::ReopenFile, file_a.Get(), file_b.Get());
    check_event(6, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 4, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    check_event(7, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 4, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    check_event(8, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 5, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    check_event(9, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 5, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    for (size_t index{6}; index < operation_events.size(); ++index) {
        BOOST_CHECK(operation_events[index].file != file_a.Get());
    }
    BOOST_CHECK(operation_events[5].event_kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock);
    BOOST_CHECK(operation_events[6].event_kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld);
}

BOOST_AUTO_TEST_CASE(multiple_reopens_preserve_fifo_and_close_order)
{
    TempFile file_a{m_path_root};
    TempFile file_b{m_path_root};
    TempFile file_c{m_path_root};
    BOOST_REQUIRE(file_a.Get() != file_b.Get());
    BOOST_REQUIRE(file_a.Get() != file_c.Get());
    BOOST_REQUIRE(file_b.Get() != file_c.Get());
    std::promise<void> worker_prelock_promise;
    auto worker_prelock_future{worker_prelock_promise.get_future()};
    std::promise<void> before_first_reopen_promise;
    auto before_first_reopen_future{before_first_reopen_promise.get_future()};
    std::promise<void> after_first_reopen_promise;
    auto after_first_reopen_future{after_first_reopen_promise.get_future()};
    std::promise<void> before_second_reopen_promise;
    auto before_second_reopen_future{before_second_reopen_promise.get_future()};
    std::promise<void> after_second_reopen_promise;
    auto after_second_reopen_future{after_second_reopen_promise.get_future()};
    Gate worker_prelock_release{0};
    Gate before_first_reopen_release{0};
    Gate before_second_reopen_release{0};
    std::atomic<bool> worker_prelock_recorded{false};
    std::atomic<bool> before_first_reopen_recorded{false};
    std::atomic<bool> after_first_reopen_recorded{false};
    std::atomic<bool> before_second_reopen_recorded{false};
    std::atomic<bool> after_second_reopen_recorded{false};
    std::array<OperationObservation, 10> operation_events{};
    std::atomic<size_t> operation_event_count{0};
    std::array<FILE*, 2> close_order{};
    std::atomic<size_t> close_count{0};

    WriterTestContext context{
        m_path_root,
        [&](const AsyncFileWriterEvent& event) noexcept {
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld ||
                event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock) {
                const size_t index{operation_event_count.fetch_add(1)};
                if (index < operation_events.size()) {
                    operation_events[index] = {
                        event.kind,
                        event.sequence,
                        event.operation_kind,
                        event.file,
                        event.replacement_file,
                    };
                }
            }
            if (event.kind == AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld &&
                !worker_prelock_recorded.exchange(true)) {
                worker_prelock_promise.set_value();
                worker_prelock_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                       event.sequence == 2 &&
                       event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                       !before_first_reopen_recorded.exchange(true)) {
                before_first_reopen_promise.set_value();
                before_first_reopen_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock &&
                       event.sequence == 2 &&
                       event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                       !after_first_reopen_recorded.exchange(true)) {
                file_a.MarkWorkerClosed();
                const size_t index{close_count.fetch_add(1)};
                if (index < close_order.size()) close_order[index] = file_a.Get();
                after_first_reopen_promise.set_value();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld &&
                       event.sequence == 4 &&
                       event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                       !before_second_reopen_recorded.exchange(true)) {
                before_second_reopen_promise.set_value();
                before_second_reopen_release.acquire();
            } else if (event.kind == AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock &&
                       event.sequence == 4 &&
                       event.operation_kind == AsyncFileWriterOperationKind::ReopenFile &&
                       !after_second_reopen_recorded.exchange(true)) {
                file_b.MarkWorkerClosed();
                const size_t index{close_count.fetch_add(1)};
                if (index < close_order.size()) close_order[index] = file_b.Get();
                after_second_reopen_promise.set_value();
            }
        },
        [&] {
            worker_prelock_release.release(RELEASE_ALL_COUNT);
            before_first_reopen_release.release(RELEASE_ALL_COUNT);
            before_second_reopen_release.release(RELEASE_ALL_COUNT);
        }};

    context.Start(file_a.Get());
    RequireReady(worker_prelock_future);
    worker_prelock_future.get();
    RequireQueued(context.writer, "A1\n");
    BOOST_REQUIRE(context.writer.Reopen(file_b.Get()) == EnqueueResult::Queued);
    RequireQueued(context.writer, "B1\n");
    BOOST_REQUIRE(context.writer.Reopen(file_c.Get()) == EnqueueResult::Queued);
    RequireQueued(context.writer, "C1\n");
    BOOST_CHECK_EQUAL(operation_event_count.load(), 0U);

    worker_prelock_release.release();
    RequireReady(before_first_reopen_future);
    before_first_reopen_future.get();
    BOOST_CHECK_EQUAL(file_a.Read(), "A1\n");
    before_first_reopen_release.release();
    RequireReady(after_first_reopen_future);
    after_first_reopen_future.get();

    RequireReady(before_second_reopen_future);
    before_second_reopen_future.get();
    BOOST_CHECK_EQUAL(file_b.Read(), "B1\n");
    before_second_reopen_release.release();
    RequireReady(after_second_reopen_future);
    after_second_reopen_future.get();

    context.writer.Flush();
    context.writer.Stop();
    BOOST_CHECK(file_a.WasClosedByWorker());
    BOOST_CHECK(file_b.WasClosedByWorker());
    BOOST_CHECK_EQUAL(file_c.Read(), "C1\n");
    BOOST_CHECK(!file_c.WasClosedByWorker());
    BOOST_REQUIRE_EQUAL(close_count.load(), close_order.size());
    BOOST_CHECK(close_order[0] == file_a.Get());
    BOOST_CHECK(close_order[1] == file_b.Get());
    BOOST_REQUIRE_EQUAL(operation_event_count.load(), operation_events.size());

    const auto check_event = [&](size_t index,
                                 AsyncFileWriterEventKind event_kind,
                                 uint64_t sequence,
                                 AsyncFileWriterOperationKind operation_kind,
                                 FILE* file,
                                 FILE* replacement_file) {
        const OperationObservation& event{operation_events[index]};
        BOOST_CHECK(event.event_kind == event_kind);
        BOOST_CHECK_EQUAL(event.sequence, sequence);
        BOOST_CHECK(event.operation_kind == operation_kind);
        BOOST_CHECK(event.file == file);
        BOOST_CHECK(event.replacement_file == replacement_file);
    };
    check_event(0, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 1, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(1, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 1, AsyncFileWriterOperationKind::WriteLine, file_a.Get(), nullptr);
    check_event(2, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 2, AsyncFileWriterOperationKind::ReopenFile, file_a.Get(), file_b.Get());
    check_event(3, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 2, AsyncFileWriterOperationKind::ReopenFile, file_a.Get(), file_b.Get());
    check_event(4, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 3, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    check_event(5, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 3, AsyncFileWriterOperationKind::WriteLine, file_b.Get(), nullptr);
    check_event(6, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 4, AsyncFileWriterOperationKind::ReopenFile, file_b.Get(), file_c.Get());
    check_event(7, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 4, AsyncFileWriterOperationKind::ReopenFile, file_b.Get(), file_c.Get());
    check_event(8, AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, 5, AsyncFileWriterOperationKind::WriteLine, file_c.Get(), nullptr);
    check_event(9, AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, 5, AsyncFileWriterOperationKind::WriteLine, file_c.Get(), nullptr);
    for (size_t index{4}; index < operation_events.size(); ++index) {
        BOOST_CHECK(operation_events[index].file != file_a.Get());
    }
    for (size_t index{8}; index < operation_events.size(); ++index) {
        BOOST_CHECK(operation_events[index].file != file_b.Get());
    }
}

BOOST_AUTO_TEST_SUITE_END()
