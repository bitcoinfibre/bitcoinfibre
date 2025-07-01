// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_FEC_H
#define BITCOIN_FEC_H

#include <assert.h>
#include <memory>
#include <stdint.h>
#include <util/fs.h>
#include <vector>

#define FEC_CHUNK_SIZE 1152
#define CM256_MAX_CHUNKS 27

#include <fec/cm256.h>
#include <fec/wirehair/wirehair.h>
#include <open_hash_set.h>
#include <random.h>

typedef std::aligned_storage<FEC_CHUNK_SIZE, 16>::type FECChunkType;
static_assert(FEC_CHUNK_SIZE % 16 == 0, "Padding of FECChunkType may hurt performance, and really shouldn't be required");
static_assert(sizeof(FECChunkType) == FEC_CHUNK_SIZE, "Padding of FECChunkType may hurt performance, and really shouldn't be required");

class BlockChunkRecvdTracker {
private:
    std::vector<bool> data_chunk_recvd_flags; // Used only for data chunks

    struct ChunkIdHasher {
        uint64_t operator()(const uint32_t elem) const { return elem; }
    };
    struct ChunkIdIsNull {
        bool operator()(const uint32_t elem) const { return elem == 0; }
    };
    open_hash_set<uint32_t, ChunkIdIsNull, ChunkIdHasher> fec_chunks_recvd;

public:
    BlockChunkRecvdTracker() {} // dummy - dont use something created like this
    BlockChunkRecvdTracker(size_t data_chunks);
    BlockChunkRecvdTracker(const BlockChunkRecvdTracker& o) =delete;
    BlockChunkRecvdTracker(BlockChunkRecvdTracker&& o) =delete;
    BlockChunkRecvdTracker& operator=(BlockChunkRecvdTracker&& other);

    inline bool CheckPresentAndMarkRecvd(uint32_t chunk_id) {
        if (chunk_id < data_chunk_recvd_flags.size()) {
            if (data_chunk_recvd_flags[chunk_id])
                return true;
            data_chunk_recvd_flags[chunk_id] = true;
        } else {
            if (fec_chunks_recvd.find_fast(chunk_id))
                return true;
            if (!fec_chunks_recvd.insert(chunk_id).second)
                return true;
        }

        return false;
    }

    inline bool CheckPresent(uint32_t chunk_id) const {
        if (chunk_id < data_chunk_recvd_flags.size()) return data_chunk_recvd_flags[chunk_id];
        return fec_chunks_recvd.find_fast(chunk_id);
    }
};

class FECDecoder;
class FECEncoder {
private:
    WirehairCodec state = NULL;
    const std::vector<unsigned char>* data;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunks;
    int32_t cm256_start_idx = -1;
    FastRandomContext rand;

    // Used only in cm256 mode:
    FECChunkType tmp_chunk;
    cm256_block cm256_blocks[CM256_MAX_CHUNKS];

public:
    // dataIn/fec_chunksIn must not change during lifetime of this object
    // fec_chunks->second[i] must be 0 for all i!
    FECEncoder(const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);
    FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);
    ~FECEncoder();

    FECEncoder(const FECEncoder&) =delete;
    FECEncoder(FECEncoder&&) =delete;

    /**
     * After BuildChunk(i), fec_chunks->first[i] will be filled with FEC data
     * and fec_chunks->second[i] will have a random chunk_id suitable to be
     * passed directly into FECDecoder::ProvideChunk or FECDecoder::HasChunk
     * (ie it will be offset by the data chunk count).
     */
    bool BuildChunk(size_t vector_idx);
    bool PrefillChunks();
};

class FECDecoder {
private:
    FECChunkType tmp_chunk;
    size_t chunk_count, chunks_recvd;
    mutable bool decodeComplete;
    BlockChunkRecvdTracker chunk_tracker;

    // Only used in wirehair mode:
    WirehairCodec state = nullptr;

    // Only used in cm256 mode:
    std::vector<FECChunkType> cm256_chunks;
    cm256_block cm256_blocks[CM256_MAX_CHUNKS];
    bool cm256_decoded = false;

    friend FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn);

public:
    FECDecoder(size_t data_size); // data_size must be <= MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR
    FECDecoder() {}
    ~FECDecoder();

    FECDecoder(const FECDecoder&) =delete;
    FECDecoder(FECDecoder&& decoder) =delete;
    FECDecoder& operator=(FECDecoder&& decoder);

    bool ProvideChunk(const unsigned char* chunk, uint32_t chunk_id);
    bool ProvideChunk(const FECChunkType* chunk, uint32_t chunk_id) { return ProvideChunk((const unsigned char*)chunk, chunk_id); }
    bool HasChunk(uint32_t chunk_id);
    bool DecodeReady() const;
    const void* GetDataPtr(uint32_t chunk_id); // Only valid until called again
};

bool BuildFECChunks(const std::vector<unsigned char>& data, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>& fec_chunks);

#endif
