// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_ASYNC_FILE_WRITER_H
#define BITCOIN_LOGGING_ASYNC_FILE_WRITER_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace BCLog {

namespace detail {

constexpr bool AsyncFileWriterRunChanged(
    uint64_t captured_generation,
    uint64_t current_generation) noexcept
{
    return current_generation != captured_generation;
}

constexpr bool AsyncFileWriterLifecycleWaitReady(
    bool stopped,
    uint64_t captured_generation,
    uint64_t current_generation) noexcept
{
    return stopped || AsyncFileWriterRunChanged(captured_generation, current_generation);
}

constexpr bool AsyncFileWriterNotFullWaitReady(
    bool running,
    std::size_t count,
    std::size_t capacity,
    uint64_t captured_generation,
    uint64_t current_generation) noexcept
{
    return AsyncFileWriterRunChanged(captured_generation, current_generation) ||
           !running || count < capacity;
}

constexpr bool AsyncFileWriterFlushWaitReady(
    uint64_t completed_sequence,
    uint64_t boundary,
    uint64_t captured_generation,
    uint64_t current_generation) noexcept
{
    return AsyncFileWriterRunChanged(captured_generation, current_generation) ||
           completed_sequence >= boundary;
}

constexpr bool AsyncFileWriterWorkerWaitReady(
    std::size_t count,
    bool draining) noexcept
{
    return count > 0 || draining;
}

} // namespace detail

enum class AsyncFileWriterEventKind {
    WorkerBeforeQueueLockLockNotHeld,
    WorkerBeforeEmptyWaitLockHeld,
    ProducerBeforeFullWaitLockHeld,
    WorkerBeforeFileOperationLockNotHeld,
    WorkerAfterFileOperationBeforeCompletionLock,
    WorkerAfterSlotReleaseLockHeld,
    FlushAfterBoundaryCapturedLockHeld,
    WorkerEmptyPredicateFalseLockHeld,
    WriteBeforeDrainingWaitLockHeld,
    StopBeforeDrainingWaitLockHeld,
    StopAfterDrainingNotificationsBeforeJoinLockNotHeld,
    StopAfterStateStoppedBeforeProgressNotifyLockNotHeld,
    ProducerFullPredicateFalseLockHeld,
};

enum class AsyncFileWriterOperationKind {
    None,
    WriteLine,
    ReopenFile,
};

struct AsyncFileWriterEvent {
    AsyncFileWriterEventKind kind;
    uint64_t sequence{0};
    AsyncFileWriterOperationKind operation_kind{AsyncFileWriterOperationKind::None};
    FILE* file{nullptr};
    FILE* replacement_file{nullptr};
};

class AsyncFileWriterTestHooks {
public:
    virtual ~AsyncFileWriterTestHooks() = default;
    virtual void OnEvent(const AsyncFileWriterEvent& event) noexcept = 0;
};

enum class EnqueueResult {
    Queued,
    Stopped,
};

class AsyncFileWriter {
public:
    explicit AsyncFileWriter(AsyncFileWriterTestHooks* hooks = nullptr);
    ~AsyncFileWriter();

    AsyncFileWriter(const AsyncFileWriter&) = delete;
    AsyncFileWriter& operator=(const AsyncFileWriter&) = delete;
    AsyncFileWriter(AsyncFileWriter&&) = delete;
    AsyncFileWriter& operator=(AsyncFileWriter&&) = delete;

    void Start(FILE* file);
    EnqueueResult Write(std::string line);
    /**
     * replacement must be non-null, open, and unbuffered. Queued means the
     * worker activates it at its FIFO sequence point and closes the old active
     * stream. The caller may remember the latest accepted pointer but may not
     * access or close worker-owned streams until Stop. A later queued Reopen
     * closes this replacement in FIFO order. Stop leaves the final active
     * stream open for the caller. Stopped leaves replacement untouched and
     * entirely caller-owned.
     */
    EnqueueResult Reopen(FILE* replacement);
    void Flush();
    void Stop();

    void WakeWaitersForTesting();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace BCLog

#endif // BITCOIN_LOGGING_ASYNC_FILE_WRITER_H
