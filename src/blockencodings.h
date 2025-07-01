// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKENCODINGS_H
#define BITCOIN_BLOCKENCODINGS_H

#include <fec.h> // For consumers - defines FEC_CHUNK_SIZE
#include <primitives/block.h>

#include <functional>
#include <streams.h>

class CTxMemPool;
class BlockValidationState;
namespace Consensus {
struct Params;
};

// Transaction compression schemes for compact block relay can be introduced by writing
// an actual formatter here.
using TransactionCompression = DefaultFormatter;

class DifferenceFormatter
{
    uint64_t m_shift = 0;

public:
    template<typename Stream, typename I>
    void Ser(Stream& s, I v)
    {
        if (v < m_shift || v >= std::numeric_limits<uint64_t>::max()) throw std::ios_base::failure("differential value overflow");
        WriteCompactSize(s, v - m_shift);
        m_shift = uint64_t(v) + 1;
    }
    template<typename Stream, typename I>
    void Unser(Stream& s, I& v)
    {
        uint64_t n = ReadCompactSize(s);
        m_shift += n;
        if (m_shift < n || m_shift >= std::numeric_limits<uint64_t>::max() || m_shift < std::numeric_limits<I>::min() || m_shift > std::numeric_limits<I>::max()) throw std::ios_base::failure("differential value overflow");
        v = I(m_shift++);
    }
};

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    SERIALIZE_METHODS(BlockTransactionsRequest, obj)
    {
        READWRITE(obj.blockhash, Using<VectorFormatter<DifferenceFormatter>>(obj.indexes));
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    uint256 blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() = default;
    explicit BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    SERIALIZE_METHODS(BlockTransactions, obj)
    {
        READWRITE(obj.blockhash, TX_WITH_WITNESS(Using<VectorFormatter<TransactionCompression>>(obj.txn)));
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransactionRef tx;

    SERIALIZE_METHODS(PrefilledTransaction, obj) { READWRITE(COMPACTSIZE(obj.index), TX_WITH_WITNESS(Using<TransactionCompression>(obj.tx))); }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
    READ_STATUS_UNSUPPORTED, // Used when the txn codec version is not supported
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    /**
     * Dummy for deserialization
     */
    CBlockHeaderAndShortTxIDs() = default;

    /**
     * @param[in]  nonce  This should be randomly generated, and is used for the siphash secret key
     */
    CBlockHeaderAndShortTxIDs(const CBlock& block, const uint64_t nonce);

    uint64_t GetShortID(const Wtxid& wtxid) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, obj)
    {
        READWRITE(obj.header, obj.nonce, Using<VectorFormatter<CustomUintFormatter<SHORTTXIDS_LENGTH>>>(obj.shorttxids), obj.prefilledtxn);
        if (ser_action.ForRead()) {
            if (obj.BlockTxCount() > std::numeric_limits<uint16_t>::max()) {
                throw std::ios_base::failure("indexes overflowed 16 bits");
            }
            obj.FillShortTxIDSelector();
        }
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txn_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0;
    const CTxMemPool* pool;
public:
    CBlockHeader header;

    // Can be overridden for testing
    using IsBlockMutatedFn = std::function<bool(const CBlock&, bool)>;
    IsBlockMutatedFn m_check_block_mutated_mock{nullptr};

    explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txn);
    bool IsTxAvailable(size_t index) const;
    // segwit_active enforces witness mutation checks just before reporting a healthy status
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, bool segwit_active);
};

// FEC-Supporting extensions

class CBlockHeaderAndLengthShortTxIDs : public CBlockHeaderAndShortTxIDs {
private:
    std::vector<uint32_t> txlens; // compressed size by CTxCompressor
    // NOTE: the prefilled transactions from the base class are not compressed
    // since that would require an out-of-band channel to communicate
    // compression version down to the base class. Note that
    // CBlockHeadersAnsShortTxIDs is used in the normal bitcoin peer protocol as
    // well, where transactions are not compressed.
    friend class PartiallyDownloadedChunkBlock;
    int height = -1; // Block height - for OOOB storage of pre-BIP34 blocks
public:
    CBlockHeaderAndLengthShortTxIDs(const CBlock& block, bool fDeterministic = false);

    // Dummy for deserialization
    CBlockHeaderAndLengthShortTxIDs() {}

    int getBlockHeight() const { return height; };
    void setBlockHeight(int h) { height = h; }
    size_t ShortTxIdCount() const { return shorttxids.size(); }

    // Fills a map from offset within a FEC-coded block to the tx index in the block
    // Returns false if this object is invalid (txlens.size() != shortxids.size())
    template <typename F>
    ReadStatus FillIndexOffsetMap(F& callback) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << height;
        s << AsBase<CBlockHeaderAndShortTxIDs>(*this);
        // NOTE: the lengths within the txlens vector are serialized directly
        // instead of serializing the vector using the VectorFormatter wrapper.
        // This is a minor optimization to avoid serializing the txlens vector
        // size, which is the same as the shorttxids vector size.
        for (size_t i = 0; i < txlens.size(); i++)
            s << VARINT(txlens[i]);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> height;
        s >> AsBase<CBlockHeaderAndShortTxIDs>(*this);
        txlens.clear();
        txlens.reserve(shorttxids.size());
        for (size_t i = 0; i < shorttxids.size(); i++) {
            uint32_t len;
            s >> VARINT(len);
            txlens.emplace_back(len);
        }
    }
};

// Valid options for the SIZE_FACTOR are 1 or 2, see cpp for more info
#define MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR 1

class ChunkCodedBlock {
private:
    std::vector<unsigned char> codedBlock;
public:
    ChunkCodedBlock(const CBlock& block, const CBlockHeaderAndLengthShortTxIDs& headerAndIDs);
    // Note that the coded block may be empty (ie prefilled txn in the header was full)
    const std::vector<unsigned char>& GetCodedBlock() const { return codedBlock; }
};

class VectorOutputStream;
class PartiallyDownloadedChunkBlock : private PartiallyDownloadedBlock {
private:
    std::map<size_t, size_t> index_offsets; // offset -> txindex
    std::vector<unsigned char> codedBlock;
    std::vector<bool> chunksAvailable;
    uint32_t remainingChunks;
    bool allTxnFromMempool;
    bool block_finalized = false;
    std::shared_ptr<CBlock> decoded_block;

    // Things used in the iterative fill-from-mempool:
    std::map<size_t, size_t>::iterator fill_coding_index_offsets_it;
    std::map<uint16_t, uint16_t> txn_prefilled; // index -> number of prefilled txn at or below index
    bool haveChunk = true;

    mutable uint256 block_hash; // Cached because its called in critical-path by udpnet

    bool SerializeTransaction(VectorOutputStream& stream, std::map<size_t, size_t>::iterator it);
public:
    PartiallyDownloadedChunkBlock(CTxMemPool* poolIn) : PartiallyDownloadedBlock(poolIn), decoded_block(std::make_shared<CBlock>()) {}

    // extra_txn is a list of extra transactions to look at, in <reference> form
    ReadStatus InitData(const CBlockHeaderAndLengthShortTxIDs& comprblock, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txn);
    ReadStatus DoIterativeFill(size_t& firstChunkProcessed);
    bool IsIterativeFillDone() const;

    bool IsBlockAvailable() const;
    bool AreAllTxnsInMempool() const;
    bool IsHeaderNull() const;
    ReadStatus FinalizeBlock();
    std::shared_ptr<const CBlock> GetBlock() const { assert(block_finalized); return decoded_block; }
    const std::vector<unsigned char>& GetCodedBlock() const { assert(AreChunksAvailable() && IsBlockAvailable()); return codedBlock; }
    uint256& GetBlockHash() const;

    size_t GetMempoolCount() const { return mempool_count; }

    // Chunk-based methods are only callable if AreChunksAvailable()
    bool AreChunksAvailable() const;
    size_t GetChunkCount() const;
    bool IsChunkAvailable(size_t chunk) const;

    // To provide a chunk, write it to GetChunk and call MarkChunkAvailable
    // The unavailable chunk pointer must be written to before GetBlock,
    // but can happen after MarkChunkAvailable
    unsigned char* GetChunk(size_t chunk);
    void MarkChunkAvailable(size_t chunk);
};

#endif // BITCOIN_BLOCKENCODINGS_H
