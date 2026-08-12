// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <logging/async_file_writer.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <semaphore>
#include <string>
#include <system_error>

namespace {

constexpr uint64_t ASYNC_LOG_QUEUE_CAPACITY{127};
constexpr uint64_t ASYNC_LOG_NORMAL_EPOCH_ITERATIONS{10};
constexpr uint64_t ASYNC_LOG_PRIMING_OPERATIONS{1};

class AsyncLogEnqueueHook final : public BCLog::AsyncFileWriterTestHooks
{
public:
    void OnEvent(const BCLog::AsyncFileWriterEvent& event) noexcept override
    {
        if (event.kind != BCLog::AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld ||
            event.sequence != 1 ||
            event.operation_kind != BCLog::AsyncFileWriterOperationKind::WriteLine) {
            return;
        }
        m_worker_blocked.release();
        m_worker_release.acquire();
    }

    void WaitUntilBlocked() { m_worker_blocked.acquire(); }

    void Release() noexcept
    {
        if (!m_released.exchange(true, std::memory_order_relaxed)) m_worker_release.release();
    }

private:
    std::binary_semaphore m_worker_blocked{0};
    std::binary_semaphore m_worker_release{0};
    std::atomic<bool> m_released{false};
};

struct FileCloser {
    fs::path path;

    void operator()(FILE* file) const noexcept
    {
        if (file != nullptr) fclose(file);
        std::error_code error;
        fs::remove(path, error);
    }
};

class AsyncLogEnqueueContext
{
public:
    explicit AsyncLogEnqueueContext(const fs::path& path)
        : m_file{fsbridge::fopen(path, "w+b"), FileCloser{path}}, m_writer{&m_hook}
    {
    }

    ~AsyncLogEnqueueContext()
    {
        m_hook.Release();
        m_writer.Stop();
    }

    void Start()
    {
        static_assert(ASYNC_LOG_PRIMING_OPERATIONS == 1);
        assert(m_file != nullptr);
        setbuf(m_file.get(), nullptr);
        m_writer.Start(m_file.get());
        assert(m_writer.Write("async-log-prime\n") == BCLog::EnqueueResult::Queued);
        m_hook.WaitUntilBlocked();
    }

    BCLog::AsyncFileWriter& Writer() { return m_writer; }

    void Finalize()
    {
        m_hook.Release();
        m_writer.Flush();
        m_writer.Stop();
    }

private:
    std::unique_ptr<FILE, FileCloser> m_file;
    AsyncLogEnqueueHook m_hook;
    BCLog::AsyncFileWriter m_writer;
};

} // namespace

static void AsyncLogEnqueueBelowCapacity(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const BasicTestingSetup>()};
    AsyncLogEnqueueContext context{testing_setup->m_path_root / "async_log_enqueue.tmp"};
    context.Start();
    BCLog::AsyncFileWriter& writer{context.Writer()};
    const std::string payload{"async-log-benchmark\n"};

    bench.warmup(0);
    if (bench.epochIterations() == 0) bench.epochIterations(ASYNC_LOG_NORMAL_EPOCH_ITERATIONS);
    assert(bench.warmup() == 0);
    assert(bench.epochIterations() > 0);
    assert(bench.epochs() <= (ASYNC_LOG_QUEUE_CAPACITY - ASYNC_LOG_PRIMING_OPERATIONS - 1) / bench.epochIterations());
    bench.run([&] {
        assert(writer.Write(payload) == BCLog::EnqueueResult::Queued);
    });

    context.Finalize();
}

BENCHMARK(AsyncLogEnqueueBelowCapacity);
