// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)


#include <blockencodings.h>      // for MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR
#include <common/args.h>
#include <common/system.h>
#include <consensus/consensus.h> // for MAX_BLOCK_SERIALIZED_SIZE
#include <fec.h>
#include <logging.h>
#include <random.h>

#include <stdio.h>
#include <string.h>
#include <util/fs.h>

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

#define FEC_CHUNK_COUNT_MAX (1 << 24)
#define CHUNK_COUNT_USES_CM256(chunks) ((chunks) <= CM256_MAX_CHUNKS)

#define CACHE_STATES_COUNT 5
static std::atomic<WirehairCodec> cache_states[CACHE_STATES_COUNT];
static inline WirehairCodec get_wirehair_codec() {
    for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
        WirehairCodec state = cache_states[i].exchange(nullptr);
        if (state) {
            return state;
        }
    }
    return nullptr;
}
static inline void return_wirehair_codec(WirehairCodec state) {
    WirehairCodec null_state = nullptr;
    for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
        if (cache_states[i].compare_exchange_weak(null_state, state)) {
            return;
        }
    }
    wirehair_free(state);
}

BlockChunkRecvdTracker::BlockChunkRecvdTracker(size_t chunk_count) :
        data_chunk_recvd_flags(CHUNK_COUNT_USES_CM256(chunk_count) ? 0xff : chunk_count),
        fec_chunks_recvd(CHUNK_COUNT_USES_CM256(chunk_count) ? 1 : chunk_count) { }

BlockChunkRecvdTracker& BlockChunkRecvdTracker::operator=(BlockChunkRecvdTracker&& other) {
    data_chunk_recvd_flags = std::move(other.data_chunk_recvd_flags);
    fec_chunks_recvd       = std::move(other.fec_chunks_recvd);
    return *this;
}

FECDecoder::FECDecoder(size_t data_size) :
        chunk_count(DIV_CEIL(data_size, FEC_CHUNK_SIZE)), chunks_recvd(0),
        decodeComplete(false), chunk_tracker(chunk_count), state(nullptr) {
    if (chunk_count < 2)
        return;

    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        cm256_chunks.reserve(chunk_count);
    } else {
        state = wirehair_decoder_create(get_wirehair_codec(), data_size, FEC_CHUNK_SIZE);
        assert(state);
    }
}

FECDecoder& FECDecoder::operator=(FECDecoder&& decoder) {
    chunk_count       = decoder.chunk_count;
    chunks_recvd      = decoder.chunks_recvd;
    decodeComplete    = decoder.decodeComplete;
    chunk_tracker     = std::move(decoder.chunk_tracker);
    if (CHUNK_COUNT_USES_CM256(decoder.chunk_count)) {
        void* orig_ptr = decoder.cm256_chunks.data();
        cm256_chunks  = std::move(decoder.cm256_chunks);
        // I dont think this is guaranteed by the spec, but we assume it to keep cm256_blocks consistent:
        assert(cm256_chunks.data() == orig_ptr);
        memcpy(cm256_blocks, decoder.cm256_blocks, sizeof(cm256_block) * decoder.chunks_recvd);
        cm256_decoded = decoder.cm256_decoded;
    } else {
        memcpy(&tmp_chunk, &decoder.tmp_chunk, sizeof(tmp_chunk));
        state         = decoder.state;
        decoder.state = nullptr;
    }
    return *this;
}

FECDecoder::~FECDecoder() {
    if (state)
        return_wirehair_codec(state);
}

bool FECDecoder::ProvideChunk(const unsigned char* chunk, uint32_t chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    if (decodeComplete)
        return true;

    // wirehair breaks if we call it twice with the same packet
    if (chunk_tracker.CheckPresentAndMarkRecvd(chunk_id))
        return true;

    chunks_recvd++;
    if (chunk_count < 2) { // For 1-packet data, just send it repeatedly...
        memcpy(&tmp_chunk, chunk, FEC_CHUNK_SIZE);
        decodeComplete = true;
    } else if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        cm256_chunks.emplace_back();
        memcpy(&cm256_chunks.back(), chunk, FEC_CHUNK_SIZE);
        cm256_blocks[chunks_recvd - 1].Block = &cm256_chunks.back();
        cm256_blocks[chunks_recvd - 1].Index = (uint8_t)chunk_id;
        if (chunk_count == chunks_recvd)
            decodeComplete = true;
    } else if (!wirehair_decode(state, chunk_id, (void*)chunk, FEC_CHUNK_SIZE))
        decodeComplete = true;

    return true;
}

bool FECDecoder::HasChunk(uint32_t chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    return decodeComplete || chunk_tracker.CheckPresent(chunk_id);
}

bool FECDecoder::DecodeReady() const {
    return decodeComplete;
}

const void* FECDecoder::GetDataPtr(uint32_t chunk_id) {
    assert(DecodeReady());
    assert(chunk_id < chunk_count);
    uint32_t chunk_size = FEC_CHUNK_SIZE;
    if (chunk_count >= 2) {
        if (CHUNK_COUNT_USES_CM256(chunk_count)) {
            if (!cm256_decoded) {
                cm256_encoder_params params { (int)chunk_count, (256 - (int)chunk_count - 1), FEC_CHUNK_SIZE };
                assert(!cm256_decode(params, cm256_blocks));
                std::sort(cm256_blocks, &cm256_blocks[chunk_count], [](const cm256_block& a, const cm256_block& b) {
                    return a.Index < b.Index;
                });
                cm256_decoded = true;
            }
            assert(cm256_blocks[uint8_t(chunk_id)].Index == chunk_id);
            return cm256_blocks[uint8_t(chunk_id)].Block;
        } else {
            assert(!wirehair_recover_block(state, chunk_id, (void*)&tmp_chunk, &chunk_size));
        }
    }
    return &tmp_chunk;
}


FECEncoder::FECEncoder(const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    size_t chunk_count = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (chunk_count < 2)
        return;

    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        for (uint8_t i = 0; i < chunk_count - 1; i++) {
            cm256_blocks[i] = cm256_block { const_cast<unsigned char*>(data->data()) + i * FEC_CHUNK_SIZE, i };
        }
        size_t expected_size = chunk_count * FEC_CHUNK_SIZE;
        if (expected_size == data->size()) {
            cm256_blocks[chunk_count - 1] = cm256_block { const_cast<unsigned char*>(data->data()) + (chunk_count - 1) * FEC_CHUNK_SIZE, (uint8_t)(chunk_count - 1) };
        } else {
            size_t fill_size = expected_size - data->size();
            memcpy(&tmp_chunk, data->data() + (chunk_count - 1) * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE - fill_size);
            memset(((unsigned char*)&tmp_chunk) + FEC_CHUNK_SIZE - fill_size, 0, fill_size);
            cm256_blocks[chunk_count - 1] = cm256_block { &tmp_chunk, (uint8_t)(chunk_count - 1) };
        }
    } else {
        state = wirehair_encoder_create(get_wirehair_codec(), data->data(), data->size(), FEC_CHUNK_SIZE);
        assert(state);
    }
}

FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    size_t chunk_count = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (chunk_count < 2)
        return;

    if (CHUNK_COUNT_USES_CM256(chunk_count)) {
        for (uint8_t i = 0; i < chunk_count - 1; i++) {
            cm256_blocks[i] = cm256_block { const_cast<unsigned char*>(data->data()) + i * FEC_CHUNK_SIZE, i };
        }
        size_t expected_size = chunk_count * FEC_CHUNK_SIZE;
        if (expected_size == data->size()) {
            cm256_blocks[chunk_count - 1] = cm256_block { const_cast<unsigned char*>(data->data()) + (chunk_count - 1) * FEC_CHUNK_SIZE, (uint8_t)(chunk_count - 1) };
        } else {
            size_t fill_size = expected_size - data->size();
            memcpy(&tmp_chunk, data->data() + (chunk_count - 1) * FEC_CHUNK_SIZE, FEC_CHUNK_SIZE - fill_size);
            memset(((unsigned char*)&tmp_chunk) + FEC_CHUNK_SIZE - fill_size, 0, fill_size);
            cm256_blocks[chunk_count - 1] = cm256_block { &tmp_chunk, (uint8_t)(chunk_count - 1) };
        }
    } else {
        state = decoder.state;
        decoder.state = NULL;

        assert(!wirehair_decoder_becomes_encoder(state));
        assert(state);
    }
}

FECEncoder::~FECEncoder() {
    if (state)
        return_wirehair_codec(state);
}

bool FECEncoder::BuildChunk(size_t vector_idx) {
    assert(vector_idx < fec_chunks->second.size());

    if (fec_chunks->second[vector_idx])
        return true;

    size_t data_chunks = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (data_chunks < 2) { // For 1-packet data, just send it repeatedly...
        memcpy(&fec_chunks->first[vector_idx], &(*data)[0], data->size());
        memset(((char*)&fec_chunks->first[vector_idx]) + data->size(), 0, FEC_CHUNK_SIZE - data->size());
        fec_chunks->second[vector_idx] = vector_idx + 1;
        return true;
    }

    uint32_t fec_chunk_id;
    // wh256 supports either unlimited chunks, or up to 256 incl data chunks
    // if data_chunks < 28 (as it switches to cm256 mode)
    if (CHUNK_COUNT_USES_CM256(data_chunks)) {
        if (cm256_start_idx == -1)
            cm256_start_idx = rand.randrange(0xff);
        fec_chunk_id = (cm256_start_idx + vector_idx) % (0xff - data_chunks);
    } else
        fec_chunk_id = rand.randrange(FEC_CHUNK_COUNT_MAX - data_chunks);
    size_t chunk_id = fec_chunk_id + data_chunks;

    if (CHUNK_COUNT_USES_CM256(data_chunks)) {
        cm256_encoder_params params { (int)data_chunks, uint8_t(256 - data_chunks - 1), FEC_CHUNK_SIZE };
        cm256_encode_block(params, cm256_blocks, chunk_id, &fec_chunks->first[vector_idx]);
    } else {
        uint32_t chunk_bytes;
        if (wirehair_encode(state, chunk_id, &fec_chunks->first[vector_idx], FEC_CHUNK_SIZE, &chunk_bytes))
            return false;

        if (chunk_bytes != FEC_CHUNK_SIZE)
            memset(((char*)&fec_chunks->first[vector_idx]) + chunk_bytes, 0, FEC_CHUNK_SIZE - chunk_bytes);
    }

    fec_chunks->second[vector_idx] = chunk_id;
    return true;
}

bool FECEncoder::PrefillChunks() {
    bool fSuccess = true;
    for (size_t i = 0; i < fec_chunks->second.size() && fSuccess; i++) {
        fSuccess = BuildChunk(i);
    }
    return fSuccess;
}

bool BuildFECChunks(const std::vector<unsigned char>& data, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>& fec_chunks) {
    FECEncoder enc(&data, &fec_chunks);
    return enc.PrefillChunks();
}

class FECInit
{
public:
    FECInit() {
        assert(!wirehair_init());
        assert(!cm256_init());
        for (size_t i = 0; i < CACHE_STATES_COUNT; i++) {
            cache_states[i] = wirehair_decoder_create(nullptr, MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR, FEC_CHUNK_SIZE);
        }
    }
} instance_of_fecinit;

