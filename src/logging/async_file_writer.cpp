// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging/async_file_writer.h>

#include <util/threadnames.h>

#include <array>
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace BCLog {

class AsyncFileWriter::Impl {
public:
    explicit Impl(AsyncFileWriterTestHooks* hooks) : m_hooks{hooks} {}

    void Start(FILE* file)
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        assert(m_state == State::Stopped);
        assert(m_count == 0);
        assert(!m_worker.joinable());
        assert(m_active_file == nullptr);
        assert(file != nullptr);

        ++m_run_generation;
        m_head = 0;
        m_tail = 0;
        m_next_sequence = 1;
        m_highest_accepted_sequence = 0;
        m_highest_completed_sequence = 0;
        m_active_file = file;
        m_state = State::Running;

        try {
            m_worker = std::thread{[this] { WorkerLoop(); }};
        } catch (...) {
            m_state = State::Stopped;
            m_active_file = nullptr;
            throw;
        }
    }

    EnqueueResult Write(std::string line)
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        const uint64_t generation{m_run_generation};

        if (m_state == State::Draining) {
            InvokeHook({AsyncFileWriterEventKind::WriteBeforeDrainingWaitLockHeld});
            m_progress.wait(lock, [this, generation] {
                return detail::AsyncFileWriterLifecycleWaitReady(
                    m_state == State::Stopped, generation, m_run_generation);
            });
            return EnqueueResult::Stopped;
        }
        if (m_state == State::Stopped) return EnqueueResult::Stopped;

        if (m_count == MAX_PENDING_OPERATIONS) {
            InvokeHook({AsyncFileWriterEventKind::ProducerBeforeFullWaitLockHeld});
        }
        m_not_full.wait(lock, [this, generation] {
            const bool ready{detail::AsyncFileWriterNotFullWaitReady(
                m_state == State::Running,
                m_count,
                MAX_PENDING_OPERATIONS,
                generation,
                m_run_generation)};
            if (!ready) {
                InvokeHook({AsyncFileWriterEventKind::ProducerFullPredicateFalseLockHeld});
            }
            return ready;
        });

        if (m_run_generation != generation) return EnqueueResult::Stopped;
        if (m_state == State::Draining) {
            InvokeHook({AsyncFileWriterEventKind::WriteBeforeDrainingWaitLockHeld});
            m_progress.wait(lock, [this, generation] {
                return detail::AsyncFileWriterLifecycleWaitReady(
                    m_state == State::Stopped, generation, m_run_generation);
            });
            return EnqueueResult::Stopped;
        }
        if (m_state == State::Stopped) return EnqueueResult::Stopped;

        assert(m_run_generation == generation);
        assert(m_state == State::Running);
        assert(m_count < MAX_PENDING_OPERATIONS);
        assert(!m_queue[m_tail].has_value());

        const uint64_t sequence{m_next_sequence++};
        m_queue[m_tail].emplace(Entry{sequence, std::move(line)});
        m_tail = (m_tail + 1) % MAX_PENDING_OPERATIONS;
        ++m_count;
        m_highest_accepted_sequence = sequence;

        lock.unlock();
        m_not_empty.notify_one();
        return EnqueueResult::Queued;
    }

    void Flush()
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        const uint64_t generation{m_run_generation};
        const uint64_t boundary{m_highest_accepted_sequence};
        InvokeHook({AsyncFileWriterEventKind::FlushAfterBoundaryCapturedLockHeld, boundary});
        if (boundary == 0 || m_highest_completed_sequence >= boundary) return;
        m_progress.wait(lock, [this, generation, boundary] {
            return detail::AsyncFileWriterFlushWaitReady(
                m_highest_completed_sequence,
                boundary,
                generation,
                m_run_generation);
        });
    }

    void Stop()
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        const uint64_t generation{m_run_generation};
        if (m_state == State::Stopped) return;

        if (m_state == State::Draining) {
            InvokeHook({AsyncFileWriterEventKind::StopBeforeDrainingWaitLockHeld});
            m_progress.wait(lock, [this, generation] {
                return detail::AsyncFileWriterLifecycleWaitReady(
                    m_state == State::Stopped, generation, m_run_generation);
            });
            return;
        }

        assert(m_state == State::Running);
        assert(m_worker.joinable());
        m_state = State::Draining;
        lock.unlock();

        m_not_empty.notify_one();
        m_not_full.notify_all();
        m_progress.notify_all();

        InvokeHook({AsyncFileWriterEventKind::StopAfterDrainingNotificationsBeforeJoinLockNotHeld});
        m_worker.join();

        lock.lock();
        assert(m_count == 0);
        assert(m_active_file == nullptr);
        assert(!m_worker.joinable());
        m_state = State::Stopped;
        lock.unlock();
        InvokeHook({AsyncFileWriterEventKind::StopAfterStateStoppedBeforeProgressNotifyLockNotHeld});
        m_progress.notify_all();
    }

    void WakeWaitersForTesting()
    {
        m_not_empty.notify_all();
        m_not_full.notify_all();
    }

private:
    static constexpr size_t MAX_PENDING_OPERATIONS{127};

    enum class State {
        Stopped,
        Running,
        Draining,
    };

    struct Entry {
        uint64_t sequence;
        std::string line;
    };

    void InvokeHook(const AsyncFileWriterEvent& event) noexcept
    {
        if (m_hooks != nullptr) m_hooks->OnEvent(event);
    }

    void WorkerLoop()
    {
        util::ThreadRename("logflush");

        while (true) {
            InvokeHook({AsyncFileWriterEventKind::WorkerBeforeQueueLockLockNotHeld});
            std::unique_lock<std::mutex> lock{m_mutex};

            if (m_state == State::Running && m_count == 0) {
                InvokeHook({AsyncFileWriterEventKind::WorkerBeforeEmptyWaitLockHeld});
            }
            m_not_empty.wait(lock, [this] {
                const bool ready{detail::AsyncFileWriterWorkerWaitReady(
                    m_count, m_state == State::Draining)};
                if (!ready) {
                    InvokeHook({AsyncFileWriterEventKind::WorkerEmptyPredicateFalseLockHeld});
                }
                return ready;
            });

            if (m_state == State::Draining && m_count == 0) {
                m_active_file = nullptr;
                lock.unlock();
                return;
            }

            assert(m_count > 0);
            assert(m_queue[m_head].has_value());
            assert(m_active_file != nullptr);
            const uint64_t sequence{m_queue[m_head]->sequence};
            std::string line{std::move(m_queue[m_head]->line)};
            FILE* const file{m_active_file};
            lock.unlock();

            InvokeHook({AsyncFileWriterEventKind::WorkerBeforeFileOperationLockNotHeld, sequence, file});
            fwrite(line.data(), 1, line.size(), file);
            InvokeHook({AsyncFileWriterEventKind::WorkerAfterFileOperationBeforeCompletionLock, sequence, file});

            lock.lock();
            assert(m_queue[m_head].has_value());
            assert(m_queue[m_head]->sequence == sequence);
            m_queue[m_head].reset();
            m_head = (m_head + 1) % MAX_PENDING_OPERATIONS;
            --m_count;
            m_highest_completed_sequence = sequence;
            InvokeHook({AsyncFileWriterEventKind::WorkerAfterSlotReleaseLockHeld, sequence});
            lock.unlock();

            m_not_full.notify_one();
            m_progress.notify_all();
        }
    }

    AsyncFileWriterTestHooks* const m_hooks;
    std::mutex m_mutex;
    std::condition_variable m_not_empty;
    std::condition_variable m_not_full;
    std::condition_variable m_progress;
    std::array<std::optional<Entry>, MAX_PENDING_OPERATIONS> m_queue;
    size_t m_head{0};
    size_t m_tail{0};
    size_t m_count{0};
    State m_state{State::Stopped};
    uint64_t m_next_sequence{1};
    uint64_t m_highest_accepted_sequence{0};
    uint64_t m_highest_completed_sequence{0};
    uint64_t m_run_generation{0};
    std::thread m_worker;
    // The worker alone may use this stream while Running or Draining. Stop
    // clears the pointer without closing it before returning access to caller.
    FILE* m_active_file{nullptr};
};

AsyncFileWriter::AsyncFileWriter(AsyncFileWriterTestHooks* hooks)
    : m_impl{std::make_unique<Impl>(hooks)}
{
}

AsyncFileWriter::~AsyncFileWriter()
{
    m_impl->Stop();
}

void AsyncFileWriter::Start(FILE* file)
{
    m_impl->Start(file);
}

EnqueueResult AsyncFileWriter::Write(std::string line)
{
    return m_impl->Write(std::move(line));
}

void AsyncFileWriter::Flush()
{
    m_impl->Flush();
}

void AsyncFileWriter::Stop()
{
    m_impl->Stop();
}

void AsyncFileWriter::WakeWaitersForTesting()
{
    m_impl->WakeWaitersForTesting();
}

} // namespace BCLog
