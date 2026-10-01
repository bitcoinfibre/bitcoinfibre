// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <fec.h>
#include <random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

namespace {

using FECChunks = std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>;

struct FECTestingSetup : BasicTestingSetup {
    FECTestingSetup()
    {
        // FECEncoder chooses recovery IDs internally. Keep the loss patterns
        // reproducible, including Wirehair's variable recovery overhead.
        SeedRandomForTest(SeedRand::ZEROS);
    }
};

size_t ChunkCount(size_t bytes)
{
    return (bytes + FEC_CHUNK_SIZE - 1) / FEC_CHUNK_SIZE;
}

std::vector<unsigned char> TestData(size_t bytes)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    return rng.randbytes(bytes);
}

FECChunks MakeChunks(size_t count)
{
    return {std::make_unique<FECChunkType[]>(count), std::vector<uint32_t>(count)};
}

FECChunkType OriginalChunk(const std::vector<unsigned char>& data, size_t id)
{
    FECChunkType chunk{};
    const size_t offset{id * FEC_CHUNK_SIZE};
    std::memcpy(&chunk, data.data() + offset, std::min<size_t>(FEC_CHUNK_SIZE, data.size() - offset));
    return chunk;
}

void ProvideRepeated(FECDecoder& decoder, const FECChunkType* chunk, uint32_t id)
{
    BOOST_REQUIRE(decoder.ProvideChunk(chunk, id));
    BOOST_CHECK(decoder.HasChunk(id));
    const bool ready{decoder.DecodeReady()};
    // Duplicates must neither count toward completion nor reach Wirehair twice.
    for (int repeat = 0; repeat < 3; ++repeat) {
        BOOST_REQUIRE(decoder.ProvideChunk(chunk, id));
        BOOST_CHECK_EQUAL(decoder.DecodeReady(), ready);
    }
}

void ProvideOriginals(FECDecoder& decoder, const std::vector<unsigned char>& data, size_t begin, size_t end)
{
    for (size_t i = begin; i < end; ++i) {
        const auto chunk{OriginalChunk(data, i)};
        ProvideRepeated(decoder, &chunk, i);
    }
}

void CheckRecovered(FECDecoder& decoder, const std::vector<unsigned char>& data)
{
    BOOST_REQUIRE(decoder.DecodeReady());
    const size_t count{ChunkCount(data.size())};
    // Read in both directions: CM256 decodes lazily, and Wirehair reuses its
    // output buffer on every GetDataPtr call. Compare before requesting more.
    for (const bool reverse : {false, true}) {
        for (size_t i = 0; i < count; ++i) {
            const size_t id{reverse ? count - 1 - i : i};
            BOOST_TEST_CONTEXT("recovered chunk=" << id << ", reverse=" << reverse) {
                BOOST_CHECK(decoder.HasChunk(id));
                const auto* recovered{static_cast<const unsigned char*>(decoder.GetDataPtr(id))};
                const size_t offset{id * FEC_CHUNK_SIZE};
                const size_t bytes{std::min<size_t>(FEC_CHUNK_SIZE, data.size() - offset)};
                BOOST_CHECK(std::equal(recovered, recovered + bytes, data.data() + offset));
            }
        }
    }
}

void ProvideRecovery(FECDecoder& decoder, const FECChunks& chunks)
{
    // Lose the first eight recovery packets and deliver the rest backwards.
    // Spare packets allow Wirehair to need more than N independent chunks.
    for (size_t i = chunks.second.size(); i > 8 && !decoder.DecodeReady();) {
        --i;
        ProvideRepeated(decoder, &chunks.first[i], chunks.second[i]);
    }
    BOOST_REQUIRE(decoder.DecodeReady());
}

void CheckLossRecovery(const std::vector<unsigned char>& data, size_t originals)
{
    const size_t count{ChunkCount(data.size())};
    auto chunks{MakeChunks(count + 32)};
    FECEncoder encoder{&data, &chunks};
    BOOST_REQUIRE(encoder.PrefillChunks());
    for (const auto id : chunks.second) BOOST_CHECK_GE(id, count);

    FECDecoder decoder{data.size()};
    BOOST_CHECK(!decoder.DecodeReady());
    // Keep only the last `originals` data chunks, also delivered backwards.
    for (size_t i = count; i > count - originals;) {
        const auto chunk{OriginalChunk(data, --i)};
        ProvideRepeated(decoder, &chunk, i);
    }
    BOOST_CHECK(!decoder.DecodeReady());
    BOOST_CHECK(!decoder.HasChunk(0));

    size_t received{originals};
    for (size_t i = chunks.second.size(); i > 8 && !decoder.DecodeReady();) {
        --i;
        if (!decoder.HasChunk(chunks.second[i])) ++received;
        ProvideRepeated(decoder, &chunks.first[i], chunks.second[i]);
        if (received < count) BOOST_CHECK(!decoder.DecodeReady());
        // CM256 is MDS: any N distinct chunks must be sufficient.
        if (count <= CM256_MAX_CHUNKS && received == count) BOOST_CHECK(decoder.DecodeReady());
    }
    CheckRecovered(decoder, data);
    // Late packets after completion must leave the reconstructed data intact.
    ProvideRepeated(decoder, &chunks.first[0], chunks.second[0]);
    CheckRecovered(decoder, data);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fec_tests, FECTestingSetup)

BOOST_AUTO_TEST_CASE(completed_single_chunk_move)
{
    for (const size_t bytes : {1, FEC_CHUNK_SIZE - 1, FEC_CHUNK_SIZE}) {
        BOOST_TEST_CONTEXT("bytes=" << bytes) {
            std::array<unsigned char, FEC_CHUNK_SIZE> expected{};
            for (size_t i = 0; i < bytes; ++i) expected[i] = static_cast<unsigned char>(i);
            std::array<unsigned char, FEC_CHUNK_SIZE> previous;
            previous.fill(0xff);

            // Overwrite a completed destination so failing to copy the payload
            // returns known, different bytes instead of uninitialized memory.
            FECDecoder decoder{bytes};
            BOOST_REQUIRE(decoder.ProvideChunk(previous.data(), 0));
            BOOST_REQUIRE(decoder.DecodeReady());
            {
                FECDecoder source{bytes};
                BOOST_REQUIRE(source.ProvideChunk(expected.data(), 0));
                BOOST_REQUIRE(source.DecodeReady());
                decoder = std::move(source);
            }
            BOOST_REQUIRE(decoder.DecodeReady());
            const auto* recovered{static_cast<const unsigned char*>(decoder.GetDataPtr(0))};
            BOOST_CHECK(std::equal(expected.begin(), expected.begin() + bytes, recovered));
        }
    }
}

BOOST_AUTO_TEST_CASE(single_chunk_repetition)
{
    for (const size_t bytes : {1, FEC_CHUNK_SIZE - 1, FEC_CHUNK_SIZE}) {
        BOOST_TEST_CONTEXT("bytes=" << bytes) {
            const auto data{TestData(bytes)};
            const auto padded{OriginalChunk(data, 0)};
            auto chunks{MakeChunks(3)};
            FECEncoder encoder{&data, &chunks};
            BOOST_REQUIRE(encoder.PrefillChunks());
            for (size_t i = 0; i < chunks.second.size(); ++i) {
                BOOST_CHECK_EQUAL(std::memcmp(&chunks.first[i], &padded, FEC_CHUNK_SIZE), 0);
                FECDecoder decoder{data.size()};
                BOOST_CHECK(!decoder.DecodeReady());
                BOOST_CHECK(!decoder.HasChunk(0));
                // Any one repetition must recover the entire message.
                ProvideRepeated(decoder, &chunks.first[i], chunks.second[i]);
                CheckRecovered(decoder, data);
                ProvideRepeated(decoder, &chunks.first[(i + 1) % 3], chunks.second[(i + 1) % 3]);
                CheckRecovered(decoder, data);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(cm256_loss_recovery)
{
    for (size_t count = 2; count <= CM256_MAX_CHUNKS; ++count) {
        for (const size_t tail : {1, FEC_CHUNK_SIZE}) {
            for (const size_t originals : {size_t{0}, count / 2, count - 1}) {
                BOOST_TEST_CONTEXT("CM256 chunks=" << count << ", tail=" << tail << ", originals=" << originals) {
                    CheckLossRecovery(TestData((count - 1) * FEC_CHUNK_SIZE + tail), originals);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(wirehair_loss_recovery)
{
    for (const size_t count : {CM256_MAX_CHUNKS + 1, CM256_MAX_CHUNKS + 2, 64, 256}) {
        for (const size_t tail : {1, FEC_CHUNK_SIZE}) {
            for (const size_t originals : {size_t{0}, count / 2, count - 1}) {
                BOOST_TEST_CONTEXT("Wirehair chunks=" << count << ", tail=" << tail << ", originals=" << originals) {
                    CheckLossRecovery(TestData((count - 1) * FEC_CHUNK_SIZE + tail), originals);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(encoder_build_and_prefill)
{
    for (const size_t count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64}) {
        BOOST_TEST_CONTEXT("chunks=" << count) {
            const auto data{TestData(count * FEC_CHUNK_SIZE - 1)};
            auto chunks{MakeChunks(3)};
            FECEncoder encoder{&data, &chunks};
            BOOST_REQUIRE(encoder.BuildChunk(2));
            const auto saved{chunks.first[2]};
            const auto saved_id{chunks.second[2]};
            BOOST_REQUIRE(encoder.BuildChunk(0));
            BOOST_REQUIRE(encoder.PrefillChunks());
            BOOST_REQUIRE(encoder.BuildChunk(2));
            BOOST_CHECK_EQUAL(chunks.second[2], saved_id);
            BOOST_CHECK_EQUAL(std::memcmp(&chunks.first[2], &saved, FEC_CHUNK_SIZE), 0);
            for (size_t i = 0; i < chunks.second.size(); ++i) {
                const auto chunk{chunks.first[i]};
                const auto id{chunks.second[i]};
                BOOST_REQUIRE(encoder.PrefillChunks());
                BOOST_CHECK_EQUAL(chunks.second[i], id);
                BOOST_CHECK_EQUAL(std::memcmp(&chunks.first[i], &chunk, FEC_CHUNK_SIZE), 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(invalid_chunk_ids)
{
    for (const size_t count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64}) {
        BOOST_TEST_CONTEXT("chunks=" << count) {
            const auto data{TestData(count * FEC_CHUNK_SIZE - 1)};
            const auto chunk{OriginalChunk(data, 0)};
            FECDecoder decoder{data.size()};
            const uint32_t out_of_range{count <= CM256_MAX_CHUNKS ? 256U : (1U << 24) + 1};
            for (size_t received = 0; received <= count; ++received) {
                const bool ready{decoder.DecodeReady()};
                for (const auto id : {out_of_range, std::numeric_limits<uint32_t>::max()}) {
                    BOOST_CHECK(!decoder.HasChunk(id));
                    BOOST_CHECK(!decoder.ProvideChunk(&chunk, id));
                    BOOST_CHECK(!decoder.HasChunk(id));
                    BOOST_CHECK_EQUAL(decoder.DecodeReady(), ready);
                }
                if (received < count) ProvideOriginals(decoder, data, received, received + 1);
            }
            CheckRecovered(decoder, data);
        }
    }
}

BOOST_AUTO_TEST_CASE(decoder_reset_and_self_move)
{
    FECDecoder decoder;
    for (const size_t count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64, 1, 64, 2}) {
        BOOST_TEST_CONTEXT("chunks=" << count) {
            const auto data{TestData(count * FEC_CHUNK_SIZE - 1)};
            decoder = FECDecoder{data.size()};
            BOOST_CHECK(!decoder.DecodeReady());
            for (size_t i = 0; i < count; ++i) BOOST_CHECK(!decoder.HasChunk(i));
            ProvideOriginals(decoder, data, 0, count / 2);
            auto& self{decoder};
            decoder = std::move(self);
            BOOST_CHECK(!decoder.DecodeReady());
            ProvideOriginals(decoder, data, count / 2, count);
            CheckRecovered(decoder, data);
            decoder = std::move(self);
            CheckRecovered(decoder, data);
        }
    }
}

BOOST_AUTO_TEST_CASE(decoder_move_assignment)
{
    for (const size_t old_count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64}) {
        auto old_data{TestData(old_count * FEC_CHUNK_SIZE)};
        for (auto& byte : old_data) byte ^= 0xff;
        for (const size_t count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64}) {
            const auto data{TestData(count * FEC_CHUNK_SIZE - 1)};
            auto chunks{MakeChunks(count + 32)};
            FECEncoder encoder{&data, &chunks};
            BOOST_REQUIRE(encoder.PrefillChunks());
            for (int progress = 0; progress < 3; ++progress) {
                BOOST_TEST_CONTEXT("old chunks=" << old_count << ", new chunks=" << count << ", progress=" << progress) {
                    FECDecoder decoder{old_data.size()};
                    ProvideOriginals(decoder, old_data, 0, old_count);
                    CheckRecovered(decoder, old_data);
                    {
                        FECDecoder source{data.size()};
                        if (progress == 0) {
                            for (size_t i = 0; i < count / 2; ++i) {
                                const size_t index{chunks.second.size() - 1 - i};
                                ProvideRepeated(source, &chunks.first[index], chunks.second[index]);
                            }
                        } else {
                            ProvideRecovery(source, chunks);
                        }
                        // Cover incomplete, complete-but-unread, and already
                        // recovered state. Recovery packets require CM256's
                        // lazy decode flag and chunk pointers to survive the move.
                        if (progress == 2) CheckRecovered(source, data);
                        decoder = std::move(source);
                    } // The moved-from decoder must not own the transferred state.
                    BOOST_CHECK_EQUAL(decoder.DecodeReady(), progress != 0);
                    if (progress == 0) {
                        BOOST_CHECK(!decoder.HasChunk(0));
                        for (size_t i = 0; i < count / 2; ++i) {
                            BOOST_CHECK(decoder.HasChunk(chunks.second[chunks.second.size() - 1 - i]));
                        }
                    }
                    ProvideRecovery(decoder, chunks);
                    CheckRecovered(decoder, data);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(decoder_to_encoder)
{
    for (const size_t count : {1, 2, CM256_MAX_CHUNKS, CM256_MAX_CHUNKS + 1, 64}) {
        for (const size_t tail : {1, FEC_CHUNK_SIZE}) {
            BOOST_TEST_CONTEXT("chunks=" << count << ", tail=" << tail) {
                const auto data{TestData((count - 1) * FEC_CHUNK_SIZE + tail)};
                auto first_hop{MakeChunks(count + 32)};
                FECEncoder sender{&data, &first_hop};
                BOOST_REQUIRE(sender.PrefillChunks());
                auto second_hop{MakeChunks(count + 32)};
                std::unique_ptr<FECEncoder> relay;
                {
                    FECDecoder decoder{data.size()};
                    ProvideRecovery(decoder, first_hop);
                    CheckRecovered(decoder, data);
                    relay = std::make_unique<FECEncoder>(std::move(decoder), &data, &second_hop);
                }
                BOOST_REQUIRE(relay->PrefillChunks());
                FECDecoder receiver{data.size()};
                ProvideRecovery(receiver, second_hop);
                CheckRecovered(receiver, data);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
