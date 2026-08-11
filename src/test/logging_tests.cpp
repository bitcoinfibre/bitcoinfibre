// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/common.h>
#include <logging.h>
#include <logging/timer.h>
#include <scheduler.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/string.h>

#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <future>
#include <ios>
#include <iostream>
#include <iterator>
#include <latch>
#include <optional>
#include <semaphore>
#include <source_location>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using util::SplitString;
using util::TrimString;

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static void ResetLogger()
{
    LogInstance().SetLogLevel(BCLog::DEFAULT_LOG_LEVEL);
    LogInstance().SetCategoryLogLevel({});
}

static std::vector<std::string> ReadDebugLogLines()
{
    std::vector<std::string> lines;
    LogInstance().FlushFileWriterForTesting();
    std::ifstream ifs{LogInstance().m_file_path.std_path()};
    for (std::string line; std::getline(ifs, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

struct LogSetup : public BasicTestingSetup {
    fs::path prev_log_path;
    fs::path tmp_log_path;
    bool prev_reopen_file;
    bool prev_print_to_file;
    bool prev_log_timestamps;
    bool prev_log_threadnames;
    bool prev_log_sourcelocations;
    std::unordered_map<BCLog::LogFlags, BCLog::Level> prev_category_levels;
    BCLog::Level prev_log_level;
    BCLog::CategoryMask prev_category_mask;

    LogSetup() : prev_log_path{LogInstance().m_file_path},
                 tmp_log_path{m_args.GetDataDirBase() / "tmp_debug.log"},
                 prev_reopen_file{LogInstance().m_reopen_file},
                 prev_print_to_file{LogInstance().m_print_to_file},
                 prev_log_timestamps{LogInstance().m_log_timestamps},
                 prev_log_threadnames{LogInstance().m_log_threadnames},
                 prev_log_sourcelocations{LogInstance().m_log_sourcelocations},
                 prev_category_levels{LogInstance().CategoryLevels()},
                 prev_log_level{LogInstance().LogLevel()},
                 prev_category_mask{LogInstance().GetCategoryMask()}
    {
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        // Prevent tests from failing when the line number of the logs changes.
        LogInstance().m_log_sourcelocations = false;

        LogInstance().SetLogLevel(BCLog::Level::Debug);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().SetCategoryLogLevel({});
        LogInstance().SetRateLimiting(nullptr);
    }

    ~LogSetup()
    {
        LogInstance().m_file_path = prev_log_path;
        LogInfo("Sentinel log to reopen log file");
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
        LogInstance().SetLogLevel(prev_log_level);
        LogInstance().SetCategoryLogLevel(prev_category_levels);
        LogInstance().SetRateLimiting(nullptr);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().EnableCategory(BCLog::LogFlags{prev_category_mask});
    }
};

namespace {

constexpr std::string_view STARTUP_SEPARATORS{"\n\n\n\n\n"};
constexpr std::ptrdiff_t RELEASE_ALL_COUNT{512};
using Gate = std::counting_semaphore<1024>;

class ReleaseGateOnDestruction
{
public:
    explicit ReleaseGateOnDestruction(Gate& gate) noexcept : m_gate{gate} {}

    ~ReleaseGateOnDestruction() noexcept
    {
        m_gate.release(RELEASE_ALL_COUNT);
    }

    ReleaseGateOnDestruction(const ReleaseGateOnDestruction&) = delete;
    ReleaseGateOnDestruction& operator=(const ReleaseGateOnDestruction&) = delete;

private:
    Gate& m_gate;
};

class LocalLoggerOwner
{
public:
    explicit LocalLoggerOwner(BCLog::Logger& logger) : m_logger{logger} {}

    ~LocalLoggerOwner()
    {
        if (m_started) m_logger.DisconnectTestLogger();
    }

    LocalLoggerOwner(const LocalLoggerOwner&) = delete;
    LocalLoggerOwner& operator=(const LocalLoggerOwner&) = delete;

    bool Start()
    {
        assert(!m_started);
        m_started = m_logger.StartLogging();
        return m_started;
    }

    void Disconnect()
    {
        assert(m_started);
        m_logger.DisconnectTestLogger();
        m_started = false;
    }

private:
    BCLog::Logger& m_logger;
    bool m_started{false};
};

void RemoveExactFile(const fs::path& path)
{
    std::error_code error;
    fs::remove(path, error);
    BOOST_REQUIRE(!error);
}

void ConfigureLocalFileLogger(BCLog::Logger& logger, const fs::path& path)
{
    RemoveExactFile(path);
    logger.m_print_to_console = false;
    logger.m_print_to_file = true;
    logger.m_log_timestamps = false;
    logger.m_log_time_micros = false;
    logger.m_log_threadnames = false;
    logger.m_log_sourcelocations = false;
    logger.m_always_print_category_level = false;
    logger.m_file_path = path;
    logger.m_reopen_file = false;
    logger.SetRateLimiting(nullptr);
}

void LogLocal(BCLog::Logger& logger, std::string_view message)
{
    logger.LogPrintStr(message, SourceLocation{__func__}, BCLog::ALL, BCLog::Level::Info, /*should_ratelimit=*/false);
}

std::string ReadLocalFile(const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    BOOST_REQUIRE(file.is_open());
    return {std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}

struct ProducerOrdinal {
    size_t producer;
    size_t ordinal;
};

std::string ProducerLine(size_t producer, size_t ordinal)
{
    return "producer=" + std::to_string(producer) + ";ordinal=" + std::to_string(ordinal) + "\n";
}

std::optional<ProducerOrdinal> ParseProducerLine(std::string_view line)
{
    constexpr std::string_view PRODUCER_PREFIX{"producer="};
    constexpr std::string_view ORDINAL_PREFIX{"ordinal="};
    if (!line.ends_with('\n')) return std::nullopt;
    line.remove_suffix(1);
    if (!line.starts_with(PRODUCER_PREFIX)) return std::nullopt;
    line.remove_prefix(PRODUCER_PREFIX.size());

    const size_t separator{line.find(';')};
    if (separator == std::string_view::npos) return std::nullopt;
    const std::string_view producer_text{line.substr(0, separator)};
    line.remove_prefix(separator + 1);
    if (!line.starts_with(ORDINAL_PREFIX)) return std::nullopt;
    line.remove_prefix(ORDINAL_PREFIX.size());
    if (producer_text.empty() || line.empty()) return std::nullopt;

    ProducerOrdinal result{};
    const auto [producer_end, producer_error]{std::from_chars(producer_text.begin(), producer_text.end(), result.producer)};
    if (producer_error != std::errc{} || producer_end != producer_text.end()) return std::nullopt;
    const auto [ordinal_end, ordinal_error]{std::from_chars(line.begin(), line.end(), result.ordinal)};
    if (ordinal_error != std::errc{} || ordinal_end != line.end()) return std::nullopt;
    return result;
}

std::vector<std::string> SplitProducerLines(std::string_view output)
{
    std::vector<std::string> lines;
    size_t offset{0};
    while (offset < output.size()) {
        const size_t newline{output.find('\n', offset)};
        BOOST_REQUIRE(newline != std::string_view::npos);
        lines.emplace_back(output.substr(offset, newline - offset + 1));
        offset = newline + 1;
    }
    return lines;
}

void CheckProducerLines(const std::vector<std::string>& lines, size_t producer_count, size_t operations_per_producer)
{
    BOOST_CHECK_EQUAL(lines.size(), producer_count * operations_per_producer);
    std::vector<std::vector<unsigned int>> seen(producer_count, std::vector<unsigned int>(operations_per_producer));
    std::vector<size_t> next_ordinal(producer_count);
    for (const std::string& line : lines) {
        const auto parsed{ParseProducerLine(line)};
        BOOST_REQUIRE(parsed.has_value());
        BOOST_REQUIRE(parsed->producer < producer_count);
        BOOST_REQUIRE(parsed->ordinal < operations_per_producer);
        BOOST_CHECK_EQUAL(parsed->ordinal, next_ordinal[parsed->producer]);
        ++next_ordinal[parsed->producer];
        BOOST_CHECK_EQUAL(seen[parsed->producer][parsed->ordinal], 0U);
        ++seen[parsed->producer][parsed->ordinal];
    }
    for (size_t producer{0}; producer < producer_count; ++producer) {
        BOOST_CHECK_EQUAL(next_ordinal[producer], operations_per_producer);
        for (size_t ordinal{0}; ordinal < operations_per_producer; ++ordinal) {
            BOOST_CHECK_EQUAL(seen[producer][ordinal], 1U);
        }
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(logger_successful_reopen_is_ordered)
{
    const fs::path path_a{m_args.GetDataDirBase() / "logger_ordered_reopen_a.log"};
    const fs::path path_b{m_args.GetDataDirBase() / "logger_ordered_reopen_b.log"};
    RemoveExactFile(path_b);
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};
    ConfigureLocalFileLogger(logger, path_a);
    BOOST_REQUIRE(owner.Start());

    LogLocal(logger, "ordered-a-1");
    LogLocal(logger, "ordered-a-2");
    logger.m_file_path = path_b;
    logger.m_reopen_file = true;
    LogLocal(logger, "ordered-b-1");
    LogLocal(logger, "ordered-b-2");
    logger.FlushFileWriterForTesting();

    BOOST_CHECK_EQUAL(ReadLocalFile(path_a), std::string{STARTUP_SEPARATORS} + "ordered-a-1\nordered-a-2\n");
    BOOST_CHECK_EQUAL(ReadLocalFile(path_b), "ordered-b-1\nordered-b-2\n");
    owner.Disconnect();
}

BOOST_AUTO_TEST_CASE(failed_reopen_keeps_old_stream_active)
{
    const fs::path original_path{m_args.GetDataDirBase() / "logger_failed_reopen.log"};
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};
    ConfigureLocalFileLogger(logger, original_path);
    BOOST_REQUIRE(owner.Start());
    logger.FlushFileWriterForTesting();
    BOOST_REQUIRE(fs::is_regular_file(original_path));

    const fs::path invalid_path{original_path / "child"};
    logger.m_file_path = invalid_path;
    logger.m_reopen_file = true;
    LogLocal(logger, "failed-reopen-current");
    LogLocal(logger, "failed-reopen-continuation");
    logger.FlushFileWriterForTesting();

    BOOST_CHECK_EQUAL(ReadLocalFile(original_path), std::string{STARTUP_SEPARATORS} + "failed-reopen-current\nfailed-reopen-continuation\n");
    BOOST_CHECK(!fs::exists(invalid_path));
    owner.Disconnect();
}

BOOST_AUTO_TEST_CASE(logger_synchronous_fallback_after_stop)
{
    const fs::path path{m_args.GetDataDirBase() / "logger_synchronous_fallback.log"};
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};
    ConfigureLocalFileLogger(logger, path);
    BOOST_REQUIRE(owner.Start());

    LogLocal(logger, "asynchronous-before-stop");
    logger.FlushFileWriterForTesting();
    logger.StopFileWriter();
    LogLocal(logger, "synchronous-after-stop");

    BOOST_CHECK_EQUAL(ReadLocalFile(path), std::string{STARTUP_SEPARATORS} + "asynchronous-before-stop\nsynchronous-after-stop\n");
    owner.Disconnect();
}

BOOST_AUTO_TEST_CASE(logger_repeated_start_disconnect_uses_distinct_paths)
{
    const std::array<fs::path, 3> paths{
        m_args.GetDataDirBase() / "logger_restart_0.log",
        m_args.GetDataDirBase() / "logger_restart_1.log",
        m_args.GetDataDirBase() / "logger_restart_2.log",
    };
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};

    for (size_t run{0}; run < paths.size(); ++run) {
        ConfigureLocalFileLogger(logger, paths[run]);
        BOOST_REQUIRE(owner.Start());
        const std::string marker{"restart-run-" + std::to_string(run)};
        LogLocal(logger, marker);
        logger.FlushFileWriterForTesting();
        owner.Disconnect();
        BOOST_CHECK_EQUAL(ReadLocalFile(paths[run]), std::string{STARTUP_SEPARATORS} + marker + "\n");
    }
}

BOOST_AUTO_TEST_CASE(logger_concurrent_producers_preserve_per_producer_order)
{
    constexpr size_t PRODUCER_COUNT{4};
    constexpr size_t OPERATIONS_PER_PRODUCER{32};
    const fs::path path{m_args.GetDataDirBase() / "logger_concurrent_producers.log"};
    std::vector<std::string> callback_lines;
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};
    ConfigureLocalFileLogger(logger, path);
    const auto callback{logger.PushBackCallback([&](const std::string& line) { callback_lines.push_back(line); })};
    BOOST_REQUIRE(owner.Start());

    std::latch producers_ready{PRODUCER_COUNT};
    Gate producers_release{0};
    std::vector<std::future<void>> producers;
    producers.reserve(PRODUCER_COUNT);
    ReleaseGateOnDestruction release_gate_on_destruction{producers_release};
    for (size_t producer{0}; producer < PRODUCER_COUNT; ++producer) {
        producers.emplace_back(std::async(std::launch::async, [&logger, &producers_ready, &producers_release, producer] {
            producers_ready.count_down();
            producers_release.acquire();
            for (size_t ordinal{0}; ordinal < OPERATIONS_PER_PRODUCER; ++ordinal) {
                LogLocal(logger, ProducerLine(producer, ordinal));
            }
        }));
    }
    producers_ready.wait();
    for (auto& producer : producers) {
        BOOST_REQUIRE(producer.valid());
        BOOST_CHECK(producer.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    }
    producers_release.release(PRODUCER_COUNT);
    for (auto& producer : producers) {
        BOOST_REQUIRE(producer.wait_for(std::chrono::seconds{120}) == std::future_status::ready);
        producer.get();
    }

    logger.FlushFileWriterForTesting();
    const std::string file_output{ReadLocalFile(path)};
    BOOST_REQUIRE(file_output.starts_with(STARTUP_SEPARATORS));
    const std::vector<std::string> file_lines{SplitProducerLines(std::string_view{file_output}.substr(STARTUP_SEPARATORS.size()))};
    CheckProducerLines(callback_lines, PRODUCER_COUNT, OPERATIONS_PER_PRODUCER);
    CheckProducerLines(file_lines, PRODUCER_COUNT, OPERATIONS_PER_PRODUCER);

    logger.DeleteCallback(callback);
    owner.Disconnect();
}

BOOST_AUTO_TEST_CASE(logger_callback_and_console_delivery_remains_ordered)
{
    const fs::path path{m_args.GetDataDirBase() / "logger_callback_console.log"};
    std::vector<std::string> callback_lines;
    BCLog::Logger logger;
    LocalLoggerOwner owner{logger};
    ConfigureLocalFileLogger(logger, path);
    logger.m_print_to_console = true;
    const auto callback{logger.PushBackCallback([&](const std::string& line) { callback_lines.push_back(line); })};
    BOOST_REQUIRE(owner.Start());

    LogLocal(logger, "callback-console-marker");
    BOOST_REQUIRE_EQUAL(callback_lines.size(), 1U);
    BOOST_CHECK_EQUAL(callback_lines.front(), "callback-console-marker\n");
    logger.FlushFileWriterForTesting();
    BOOST_CHECK_EQUAL(ReadLocalFile(path), std::string{STARTUP_SEPARATORS} + "callback-console-marker\n");

    logger.DeleteCallback(callback);
    owner.Disconnect();
}

BOOST_AUTO_TEST_CASE(logging_timer)
{
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    const std::string_view result_prefix{"tests: msg ("};
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("msg").substr(0, result_prefix.size()), result_prefix);
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintStr, LogSetup)
{
    LogInstance().m_log_sourcelocations = true;

    struct Case {
        std::string msg;
        BCLog::LogFlags category;
        BCLog::Level level;
        std::string prefix;
        SourceLocation loc;
    };

    std::vector<Case> cases = {
        {"foo1: bar1", BCLog::NET, BCLog::Level::Debug, "[net] ", SourceLocation{__func__}},
        {"foo2: bar2", BCLog::NET, BCLog::Level::Info, "[net:info] ", SourceLocation{__func__}},
        {"foo3: bar3", BCLog::ALL, BCLog::Level::Debug, "[debug] ", SourceLocation{__func__}},
        {"foo4: bar4", BCLog::ALL, BCLog::Level::Info, "", SourceLocation{__func__}},
        {"foo5: bar5", BCLog::NONE, BCLog::Level::Debug, "[debug] ", SourceLocation{__func__}},
        {"foo6: bar6", BCLog::NONE, BCLog::Level::Info, "", SourceLocation{__func__}},
    };

    std::vector<std::string> expected;
    for (auto& [msg, category, level, prefix, loc] : cases) {
        expected.push_back(tfm::format("[%s:%s] [%s] %s%s", util::RemovePrefix(loc.file_name(), "./"), loc.line(), loc.function_name_short(), prefix, msg));
        LogInstance().LogPrintStr(msg, std::move(loc), category, level, /*should_ratelimit=*/false);
    }
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros, LogSetup)
{
    LogInstance().EnableCategory(BCLog::NET);
    LogTrace(BCLog::NET, "foo6: %s", "bar6"); // not logged
    LogDebug(BCLog::NET, "foo7: %s", "bar7");
    LogInfo("foo8: %s", "bar8");
    LogWarning("foo9: %s", "bar9");
    LogError("foo10: %s", "bar10");
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    std::vector<std::string> expected = {
        "[net] foo7: bar7",
        "foo8: bar8",
        "[warning] foo9: bar9",
        "[error] foo10: bar10",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros_CategoryName, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    const auto concatenated_category_names = LogInstance().LogCategoriesString();
    std::vector<std::pair<BCLog::LogFlags, std::string>> expected_category_names;
    const auto category_names = SplitString(concatenated_category_names, ',');
    for (const auto& category_name : category_names) {
        BCLog::LogFlags category;
        const auto trimmed_category_name = TrimString(category_name);
        BOOST_REQUIRE(GetLogCategory(category, trimmed_category_name));
        expected_category_names.emplace_back(category, trimmed_category_name);
    }

    std::vector<std::string> expected;
    for (const auto& [category, name] : expected_category_names) {
        LogDebug(category, "foo: %s\n", "bar");
        std::string expected_log = "[";
        expected_log += name;
        expected_log += "] foo: bar";
        expected.push_back(expected_log);
    }

    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_SeverityLevels, LogSetup)
{
    LogInstance().SetLogLevel(BCLog::Level::Debug);
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    LogInstance().SetCategoryLogLevel(/*category_str=*/"net", /*level_str=*/"info");

    // Global log level
    LogInfo("info_%s", 1);
    LogTrace(BCLog::HTTP, "trace_%s. This log level is lower than the global one.", 2);
    LogDebug(BCLog::HTTP, "debug_%s", 3);
    LogWarning("warn_%s", 4);
    LogError("err_%s", 5);

    // Category-specific log level
    LogDebug(BCLog::NET, "debug_%s. This log level is the same as the global one but lower than the category-specific one, which takes precedence.", 6);

    std::vector<std::string> expected = {
        "info_1",
        "[http] debug_3",
        "[warning] warn_4",
        "[error] err_5",
    };
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_Conf, LogSetup)
{
    // Set global log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=debug"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);
    }

    // Set category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=net:trace"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::DEFAULT_LOG_LEVEL);

        const auto& category_levels{LogInstance().CategoryLevels()};
        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_REQUIRE(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);
    }

    // Set both global log level and category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=debug", "-loglevel=net:trace", "-loglevel=http:info"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(4, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);

        const auto& category_levels{LogInstance().CategoryLevels()};
        BOOST_CHECK_EQUAL(category_levels.size(), 2);

        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_CHECK(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);

        const auto http_it{category_levels.find(BCLog::LogFlags::HTTP)};
        BOOST_CHECK(http_it != category_levels.end());
        BOOST_CHECK_EQUAL(http_it->second, BCLog::Level::Info);
    }
}

struct ScopedScheduler {
    CScheduler scheduler{};

    ScopedScheduler()
    {
        scheduler.m_service_thread = std::thread([this] { scheduler.serviceQueue(); });
    }
    ~ScopedScheduler()
    {
        scheduler.stop();
    }
    void MockForwardAndSync(std::chrono::seconds duration)
    {
        scheduler.MockForward(duration);
        std::promise<void> promise;
        scheduler.scheduleFromNow([&promise] { promise.set_value(); }, 0ms);
        promise.get_future().wait();
    }
    std::shared_ptr<BCLog::LogRateLimiter> GetLimiter(size_t max_bytes, std::chrono::seconds window)
    {
        auto sched_func = [this](auto func, auto w) {
            scheduler.scheduleEvery(std::move(func), w);
        };
        return BCLog::LogRateLimiter::Create(sched_func, max_bytes, window);
    }
};

BOOST_AUTO_TEST_CASE(logging_log_rate_limiter)
{
    uint64_t max_bytes{1024};
    auto reset_window{1min};
    ScopedScheduler scheduler{};
    auto limiter_{scheduler.GetLimiter(max_bytes, reset_window)};
    auto& limiter{*Assert(limiter_)};

    using Status = BCLog::LogRateLimiter::Status;
    auto source_loc_1{SourceLocation{__func__}};
    auto source_loc_2{SourceLocation{__func__}};

    // A fresh limiter should not have any suppressions
    BOOST_CHECK(!limiter.SuppressionsActive());

    // Resetting an unused limiter is fine
    limiter.Reset();
    BOOST_CHECK(!limiter.SuppressionsActive());

    // No suppression should happen until more than max_bytes have been consumed
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes - 1, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::UNSUPPRESSED);
    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::STILL_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // Location 2  should not be affected by location 1's suppression
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // After reset_window time has passed, all suppressions should be cleared.
    scheduler.MockForwardAndSync(reset_window);

    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
}

BOOST_AUTO_TEST_CASE(logging_log_limit_stats)
{
    BCLog::LogRateLimiter::Stats stats(BCLog::RATELIMIT_MAX_BYTES);

    // Check that stats gets initialized correctly.
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    const uint64_t MESSAGE_SIZE{BCLog::RATELIMIT_MAX_BYTES / 2};
    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE * 2);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    // Consuming more bytes after already having consumed RATELIMIT_MAX_BYTES should fail.
    BOOST_CHECK(!stats.Consume(500));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, uint64_t{0});
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{500});
}

namespace {

enum class Location {
    INFO_1,
    INFO_2,
    DEBUG_LOG,
    INFO_NOLIMIT,
};

void LogFromLocation(Location location, const std::string& message) {
    switch (location) {
    case Location::INFO_1:
        LogInfo("%s\n", message);
        return;
    case Location::INFO_2:
        LogInfo("%s\n", message);
        return;
    case Location::DEBUG_LOG:
        LogDebug(BCLog::LogFlags::HTTP, "%s\n", message);
        return;
    case Location::INFO_NOLIMIT:
        LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Info, /*should_ratelimit=*/false, "%s\n", message);
        return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/**
 * For a given `location` and `message`, ensure that the on-disk debug log behaviour resembles what
 * we'd expect it to be for `status` and `suppressions_active`.
 */
void TestLogFromLocation(Location location, const std::string& message,
                         BCLog::LogRateLimiter::Status status, bool suppressions_active,
                         std::source_location source = std::source_location::current())
{
    BOOST_TEST_INFO_SCOPE("TestLogFromLocation called from " << source.file_name() << ":" << source.line());
    using Status = BCLog::LogRateLimiter::Status;
    if (!suppressions_active) assert(status == Status::UNSUPPRESSED); // developer error

    LogInstance().FlushFileWriterForTesting();
    {
        std::ofstream ofs(LogInstance().m_file_path.std_path(), std::ios::out | std::ios::trunc); // clear debug log
        BOOST_REQUIRE(ofs.is_open());
    }
    LogFromLocation(location, message);
    auto log_lines{ReadDebugLogLines()};
    BOOST_TEST_INFO_SCOPE(log_lines.size() << " log_lines read: \n" << util::Join(log_lines, "\n"));

    if (status == Status::STILL_SUPPRESSED) {
        BOOST_CHECK_EQUAL(log_lines.size(), 0);
        return;
    }

    if (status == Status::NEWLY_SUPPRESSED) {
        BOOST_REQUIRE_EQUAL(log_lines.size(), 2);
        BOOST_CHECK(log_lines[0].starts_with("[*] [warning] Excessive logging detected"));
        log_lines.erase(log_lines.begin());
    }
    BOOST_REQUIRE_EQUAL(log_lines.size(), 1);
    auto& payload{log_lines.back()};
    BOOST_CHECK_EQUAL(suppressions_active, payload.starts_with("[*]"));
    BOOST_CHECK(payload.ends_with(message));
}

} // namespace

BOOST_FIXTURE_TEST_CASE(logging_filesize_rate_limit, LogSetup)
{
    using Status = BCLog::LogRateLimiter::Status;
    LogInstance().m_log_timestamps = false;
    LogInstance().m_log_sourcelocations = false;
    LogInstance().m_log_threadnames = false;
    LogInstance().EnableCategory(BCLog::LogFlags::HTTP);

    constexpr int64_t line_length{1024};
    constexpr int64_t num_lines{10};
    constexpr int64_t bytes_quota{line_length * num_lines};
    constexpr auto time_window{1h};

    ScopedScheduler scheduler{};
    auto limiter{scheduler.GetLimiter(bytes_quota, time_window)};
    LogInstance().SetRateLimiting(limiter);

    const std::string log_message(line_length - 1, 'a'); // subtract one for newline

    for (int i = 0; i < num_lines; ++i) {
        TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    }
    TestLogFromLocation(Location::INFO_1, "a", Status::NEWLY_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_1, "b", Status::STILL_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_2, "c", Status::UNSUPPRESSED, /*suppressions_active=*/true);
    {
        scheduler.MockForwardAndSync(time_window);
        BOOST_CHECK(ReadDebugLogLines().back().starts_with("[warning] Restarting logging"));
    }
    // Check that logging from previously suppressed location is unsuppressed again.
    TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    // Check that conditional logging, and unconditional logging with should_ratelimit=false is
    // not being ratelimited.
    for (Location location : {Location::DEBUG_LOG, Location::INFO_NOLIMIT}) {
        for (int i = 0; i < num_lines + 2; ++i) {
            TestLogFromLocation(location, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
