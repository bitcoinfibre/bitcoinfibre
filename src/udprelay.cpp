// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udprelay.h>

#include <blockencodings.h>
#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/consensus.h>  // for MAX_BLOCK_SERIALIZED_SIZE
#include <consensus/validation.h> // for BlockValidationState/TxValidationState
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <streams.h>
#include <util/thread.h>
#include <validation.h>
#include <node/protocol_version.h>

#include <algorithm>
#include <condition_variable>
#include <optional>
#include <queue>
#include <sstream>
#include <filesystem>
#include <thread>

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())
#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

static CService TRUSTED_PEER_DUMMY;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>> mapPartialBlocks;
static std::unordered_set<uint64_t> setBlocksRelayed;
// In cases where we receive a block without its previous block, or a block
// which is already (to us) an orphan, we will not get a UDPRelayBlock
// callback. However, we do not want to re-process the still-happening stream
// of packets into more ProcessNewBlock calls, so we have to keep a separate
// set here.
static std::set<std::pair<uint64_t, CService>> setBlocksReceived;

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it) {
    uint64_t hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify nodesWithChunksAvailableSet, as it might be "read-only" due to currentlyProcessing
    for (const auto& node : it->second->nodesWithChunksAvailableSet) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;
        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key) {
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t hash_prefix) {
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

static inline void SendMessageToNode(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it) {
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;
    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);

    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();
    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER) {
            if (chunks_avail_it->second.IsHeaderChunkAvailable(le32toh_internal(msg.msg.block.chunk_id)))
                return;
        } else {
            if (!chunks_avail_it->second.IsBlockDataChunkCountSet())
                chunks_avail_it->second.SetBlockDataChunkCount(DIV_CEIL(le32toh_internal(msg.msg.block.obj_length), sizeof(UDPBlockMessage::data)));
            if (chunks_avail_it->second.IsBlockChunkAvailable(le32toh_internal(msg.msg.block.chunk_id)))
                return;
        }
    }

    SendMessage(msg, length, high_prio, it);

    if (use_chunks_avail) {
        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(le32toh_internal(msg.msg.block.chunk_id));
        else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS)
            chunks_avail_it->second.SetBlockChunkAvailable(le32toh_internal(msg.msg.block.chunk_id));
    }
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix) {
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessageToNode(msg, length, high_prio, hash_prefix, it);
}

static void CopyMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, size_t msg_chunks, uint16_t chunk_id) {
    msg.msg.block.chunk_id = htole16_internal(chunk_id);

    size_t msg_size = chunk_id == msg_chunks - 1 ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.msg.block.data);
    if (msg_size == 0) msg_size = FEC_CHUNK_SIZE;
    memcpy(msg.msg.block.data, &data[chunk_id * FEC_CHUNK_SIZE], msg_size);
    if (msg_size != sizeof(msg.msg.block.data))
        memset(&msg.msg.block.data[msg_size], 0, sizeof(msg.msg.block.data) - msg_size);
}

// Note that algo is broken if you use both high_prio_chunks_per_peer and chunk_limit!
static void SendMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix, const size_t chunk_limit) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    size_t chunks_sent_per_peer = 0;
    bool high_prio = high_prio_chunks_per_peer;
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < msg_chunks && i < chunk_limit; i++) {
            CopyMessageData(msg, data, msg_chunks, i);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end()) {
                send_it = mapUDPNodes.begin();
                chunks_sent_per_peer++;
                if (high_prio && chunks_sent_per_peer >= high_prio_chunks_per_peer) high_prio = false;
            }
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(&data, &fec_data) {}

    DataFECer(FECDecoder&& decoder, const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(std::move(decoder), &data, &fec_data) {}
};

static void CopyFECData(UDPMessage& msg, DataFECer& fec, size_t msg_chunks, size_t array_idx) {
    assert(fec.enc.BuildChunk(array_idx)); // TODO: Handle errors?
    assert(fec.fec_data.second[array_idx] < (1 << 24));
    msg.msg.block.chunk_id = htole32_internal(fec.fec_data.second[array_idx]);
    memcpy(msg.msg.block.data, &fec.fec_data.first[array_idx], FEC_CHUNK_SIZE);
}

static void SendFECData(UDPMessage& msg, DataFECer& fec, const size_t msg_chunks, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix) {
    assert(fec.fec_chunks > 9);

    size_t chunks_sent_per_peer = 0;
    bool high_prio = high_prio_chunks_per_peer;
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (size_t i = 0; i < fec.fec_chunks; i++) {
            CopyFECData(msg, fec, msg_chunks, i);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end()) {
                send_it = mapUDPNodes.begin();
                chunks_sent_per_peer++;
                if (high_prio && chunks_sent_per_peer >= high_prio_chunks_per_peer) high_prio = false;
            }
        }
    }
}

static inline void FillCommonMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, uint8_t type, const std::vector<unsigned char>& data) {
    msg.header.msg_type        = type;
    msg.msg.block.hash_prefix  = htole64_internal(hash_prefix);
    msg.msg.block.obj_length   = htole32_internal(data.size());
}

static inline void FillBlockMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, UDPMessageType type, const std::vector<unsigned char>& data) {
    // First fill in common message elements
    FillCommonMessageHeader(msg, hash_prefix, type | HAVE_BLOCK, data);
}

static void SendFECedData(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    FillBlockMessageHeader(msg, hash_prefix, type, data);

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER) {
        // Block headers are all high priority for the data itself,
        // and 3 packets of high priority for the FEC, after that if
        // we have block data available it should be sent.
        SendMessageData(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, std::numeric_limits<size_t>::max());
        SendFECData(msg, fec, msg_chunks, 3, hash_prefix);
    } else {
        // First 10 FEC chunks are high priority, then everything is
        // low. This should be sufficient to reconstruct many blocks
        // that only missed a handful of chunks, then revert to
        // sending header chunks until we've sent them all.
        SendFECData(msg, fec, msg_chunks, 10, hash_prefix);

        // We also benchmark sending pre-calced data here to ensure there
        // isn't a lot of overhead here...
        const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
        std::chrono::steady_clock::time_point start;
        if (fBench)
            start = std::chrono::steady_clock::now();
        SendMessageData(msg, data, 0, hash_prefix, std::numeric_limits<size_t>::max());
        if (fBench) {
            std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
            LogPrintf("UDP: Sent block data chunks in %lf ms\n", to_millis_double(finished - start));
        }
    }
}

static void SendLimitedDataChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data);

    SendMessageData(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, 3); // Send 3 packets to each peer, in RR
}

static std::unique_ptr<std::thread> process_block_thread;

void UDPRelayBlock(const CBlock& block) {
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock(block.GetHash());
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    if (maybe_have_write_nodes) { // Scope for partial_block_lock and partial_block_ptr
        const std::vector<unsigned char> *block_chunks = NULL;
        bool skipEncode = false;
        std::unique_lock<std::mutex> partial_block_lock;
        std::shared_ptr<PartialBlockData> partial_block_ptr;
        bool inUDPProcess = process_block_thread && std::this_thread::get_id() == process_block_thread->get_id();
        if (inUDPProcess) {
            lock.lock();

            auto it = mapPartialBlocks.find(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
            if (it != mapPartialBlocks.end() && it->second->currentlyProcessing) {
                partial_block_lock = std::unique_lock<std::mutex>(it->second->state_mutex); // Locked after cs_mapUDPNodes
                if (it->second->block_data.AreChunksAvailable()) {
                    if (fBench)
                        LogPrintf("UDP: Building FEC chunks from decoded block\n");
                    skipEncode = true;
                    partial_block_ptr = it->second;
                    block_chunks = &it->second->block_data.GetCodedBlock();
                }
            }

            // We unlock everything here to let the net thread relay packets,
            // but continue to use data which is theoretically under the locks.
            // This is OK - we get a copy of the shared_ptr and hold it in
            // partial_block_ptr so it wont be destroyed out from under us, and
            // are only using the chunks from PartiallyDownloadedChunkBlock and
            // the decoder, both of which, once available, will never become
            // un-available or be modified by any other thread (due to the
            // currentlyProcessing checks made in the net thread).
            // We should not otherwise be making assumptions about availability of
            // block-related data, but eg the message send functions check for the
            // availability of ChunkAvailableSets prior to access.
            if (partial_block_lock)
                partial_block_lock.unlock();
            lock.unlock();
        }

        std::chrono::steady_clock::time_point initd;
        if (fBench)
            initd = std::chrono::steady_clock::now();

        ChunkCodedBlock *codedBlock = (ChunkCodedBlock*) alloca(sizeof(ChunkCodedBlock));
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, true);
        std::vector<unsigned char> data;
        data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
        VectorOutputStream stream(&data);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        DataFECer header_fecer(data, (min_per_node_mbps.load(std::memory_order_relaxed) * 1024 * 1024 / 8 / 1000 / PACKET_SIZE) + 10); // 1ms + 10 chunks of header FEC

        DataFECer *block_fecer = (DataFECer*) alloca(sizeof(DataFECer));
        size_t data_fec_chunks = 0;
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                if (skipEncode) {
                    // If we get here, we are currently in the processing thread
                    // and have partial_block_ptr set. Additionally, because
                    // partial_block_ptr->block_data has chunks, the FEC decoder
                    // was initialized and fed FEC/data, meaning even if no FEC
                    // chunks were used to reconstruct the FECDecoder object is
                    // fully primed to be converted to a FECEncoder!
                    new (block_fecer) DataFECer(std::move(partial_block_ptr->decoder), *block_chunks, data_fec_chunks);
                } else {
                    new (block_fecer) DataFECer(*block_chunks, data_fec_chunks);
                }
                block_fecer->enc.PrefillChunks();
            }
        }

        std::chrono::steady_clock::time_point feced;
        if (fBench)
            feced = std::chrono::steady_clock::now();

        // We do all the expensive calculations before locking cs_mapUDPNodes
        // so that the forward-packets-without-block logic in HandleBlockMessage
        // continues without interruption as long as possible
        if (!lock)
            lock.lock();

        if (mapUDPNodes.empty())
            return;

        if (setBlocksRelayed.count(hash_prefix))
            return;

        SendFECedData(hashBlock, MSG_TYPE_BLOCK_HEADER, data, header_fecer);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }

            // Because we need the coded block's size to init block decoding, it
            // is important we get the first block packet out to peers ASAP. Thus,
            // we go ahead and send the first few non-FEC block packets here.
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                SendLimitedDataChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!block_chunks->empty()) {
                new (block_fecer) DataFECer(*block_chunks, data_fec_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_fec_initd;
        if (fBench)
            block_fec_initd = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!block_chunks->empty())
            SendFECedData(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks, *block_fecer);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s in %lf %lf %lf %lf %lf %lf %lf ms with %lu header chunks\n", hashBlock.ToString(), to_millis_double(initd - start), to_millis_double(coded - initd), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(block_fec_initd - block_coded), to_millis_double(all_sent - block_fec_initd), header_fecer.fec_chunks);
            if (!inUDPProcess){
                size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(block));
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), block_size);
            }
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        if (!skipEncode)
            codedBlock->~ChunkCodedBlock();

        if (!block_chunks->empty())
            block_fecer->~DataFECer();

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<UDPMessage>& msgs) {
    const Wtxid hash(tx.GetWitnessHash());
    const uint64_t hash_prefix = hash.ToUint256().GetUint64(0);

    std::vector<unsigned char> data;
    VectorOutputStream stream(&data);
    stream << TX_WITH_WITNESS(tx);

    const size_t data_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    DataFECer fecer(data, data_chunks * 1.2 + 1);

    msgs.resize(data_chunks + fecer.fec_chunks);
    for (size_t i = 0; i < data_chunks; i++) {
        FillCommonMessageHeader(msgs[i], hash_prefix, MSG_TYPE_TX_CONTENTS, data);
        CopyMessageData(msgs[i], data, data_chunks, i);
    }
    for (size_t i = 0; i < fecer.fec_chunks; i++) {
        FillCommonMessageHeader(msgs[i + data_chunks], hash_prefix, MSG_TYPE_TX_CONTENTS, data);
        CopyFECData(msgs[i + data_chunks], fecer, data_chunks, i);
    }
}

void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs) {
    const uint256 hashBlock(block.GetHash());
    const uint64_t hash_prefix = hashBlock.GetUint64(0);

    CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, true);

    std::vector<unsigned char> data;
    data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
    VectorOutputStream stream(&data);
    stream << headerAndIDs;

    const size_t header_data_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    DataFECer header_fecer(data, std::max(size_t(30), header_data_chunks * 2 + 8)); // Generate enough to recover header 3 times
    const size_t send_window = header_fecer.fec_chunks / 2;

    msgs.resize(header_data_chunks + header_fecer.fec_chunks);
    for (size_t i = 0; i < header_data_chunks; i++) {
        FillBlockMessageHeader(msgs[i], hash_prefix, MSG_TYPE_BLOCK_HEADER, data);
        CopyMessageData(msgs[i], data, header_data_chunks, i);
    }
    size_t offset = header_data_chunks;
    for (size_t i = 0; i < send_window; i++) {
        FillBlockMessageHeader(msgs[i + offset], hash_prefix, MSG_TYPE_BLOCK_HEADER, data);
        CopyFECData(msgs[i + offset], header_fecer, header_data_chunks, i);
    }
    offset += send_window;

    ChunkCodedBlock codedBlock(block, headerAndIDs);
    const std::vector<unsigned char>& block_chunks = codedBlock.GetCodedBlock();

    size_t data_data_chunks = DIV_CEIL(block_chunks.size(), FEC_CHUNK_SIZE);
    size_t data_fec_chunks = data_data_chunks + 10; //TODO: Pick something different?

    if (!block_chunks.empty()) {
        msgs.resize(msgs.size() + data_data_chunks + data_fec_chunks);

        for (size_t i = 0; i < send_window && i < data_data_chunks; i++) {
            FillBlockMessageHeader(msgs[i + offset], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, block_chunks);
            CopyMessageData(msgs[i + offset], block_chunks, data_data_chunks, i);
        }
        offset += std::min(send_window, data_data_chunks);
    }

    for (size_t i = send_window; i < header_fecer.fec_chunks; i++) {
        FillBlockMessageHeader(msgs[i - send_window + offset], hash_prefix, MSG_TYPE_BLOCK_HEADER, data);
        CopyFECData(msgs[i - send_window + offset], header_fecer, header_data_chunks, i);
    }
    offset += header_fecer.fec_chunks - send_window; // fec_chunks is divisible by 2, so this is fine

    if (!block_chunks.empty()) {
        for (size_t i = send_window; i < data_data_chunks; i++) {
            FillBlockMessageHeader(msgs[i - send_window + offset], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, block_chunks);
            CopyMessageData(msgs[i - send_window + offset], block_chunks, data_data_chunks, i);
        }
        offset += (size_t)std::max(int64_t(0), int64_t(data_data_chunks) - int64_t(send_window));

        DataFECer block_fecer(block_chunks, data_fec_chunks);
        for (size_t i = 0; i < block_fecer.fec_chunks; i++) {
            FillBlockMessageHeader(msgs[i + offset], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, block_chunks);
            CopyFECData(msgs[i + offset], block_fecer, data_data_chunks, i);
        }
    }
}

static std::mutex block_process_mutex;
static std::condition_variable block_process_cv;
static std::atomic_bool block_process_shutdown(false);
static std::vector<std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>> block_process_queue;

static void DoBackgroundBlockProcessing(const std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>& block_data) {
    // If we just blindly call ProcessNewBlock here, we have a cs_main/cs_mapUDPNodes inversion
    // (actually because fucking P2P code calls everything with cs_main already locked).
    // Instead we pass the processing back to ProcessNewBlockThread without cs_mapUDPNodes
    std::unique_lock<std::mutex> lock(block_process_mutex);
    block_process_queue.emplace_back(block_data);
    lock.unlock();
    block_process_cv.notify_all();
}

static void ProcessBlockThread(ChainstateManager* chainman, PeerManager* peer_manager) {
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);

    while (true) {
        std::unique_lock<std::mutex> process_lock(block_process_mutex);
        while (block_process_queue.empty() && !block_process_shutdown)
            block_process_cv.wait(process_lock);
        if (block_process_shutdown)
            return;
        // To avoid vector re-allocation we pop_back, so its secretly a stack, shhhhh, dont tell anyone
        std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>> process_block = block_process_queue.back();
        PartialBlockData& block = *process_block.second;
        block_process_queue.pop_back();
        process_lock.unlock();

        bool more_work;
        std::unique_lock<std::mutex> lock(block.state_mutex);
        do {
            more_work = false;
            if (block.is_header_processing) {
                std::chrono::steady_clock::time_point decode_start;
                if (fBench)
                    decode_start = std::chrono::steady_clock::now();

                for (uint32_t i = 0; i < DIV_CEIL(block.obj_length, sizeof(UDPBlockMessage::data)); i++) {
                    const void* data_ptr = block.decoder.GetDataPtr(i);
                    assert(data_ptr);
                    memcpy(&block.data_recvd[i * sizeof(UDPBlockMessage::data)], data_ptr, sizeof(UDPBlockMessage::data));
                }

                std::chrono::steady_clock::time_point data_copied;
                if (fBench)
                    data_copied = std::chrono::steady_clock::now();

                CBlockHeaderAndLengthShortTxIDs header;
                try {
                    VectorInputStream stream(&block.data_recvd);
                    stream >> header;
                } catch (std::ios_base::failure& e) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (process_block.first.second == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Failed to decode received header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        LogPrintf("UDP: Failed to decode received header and short txids from %s, disconnecting\n", process_block.first.second.ToStringAddrPort());
                        const auto it = mapUDPNodes.find(process_block.first.second);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                    break;
                }
                std::chrono::steady_clock::time_point header_deserialized;
                if (fBench)
                    header_deserialized = std::chrono::steady_clock::now();

                    auto extra_txn = peer_manager->GetExtraTxnForCompact();
                    ReadStatus decode_status = block.ProvideHeaderData(header, *extra_txn);
                if (decode_status != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (decode_status == READ_STATUS_INVALID) {
                        if (process_block.first.second == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Got invalid header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                        else {
                            LogPrintf("UDP: Got invalid header and short txids from %s, disconnecting\n", process_block.first.second.ToStringAddrPort());
                            const auto it = mapUDPNodes.find(process_block.first.second);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    } else
                        LogPrintf("UDP: Failed to read header and short txids\n");

                    // Dont remove the block, let it time out...
                    break;
                }

                if (block.block_data.IsBlockAvailable())
                    block.is_decodeable.store(true, std::memory_order_release);
                block.is_header_processing.store(false, std::memory_order_release);

                if (block.is_decodeable.load(std::memory_order_acquire))
                    more_work = true;
                else
                    lock.unlock();

                if (fBench) {
                    std::chrono::steady_clock::time_point header_provided(std::chrono::steady_clock::now());
                    LogPrintf("UDP: Got full header and shorttxids from %s in %lf %lf %lf ms\n", block.nodeHeaderRecvd.ToStringAddrPort(), to_millis_double(data_copied - decode_start), to_millis_double(header_deserialized - data_copied), to_millis_double(header_provided - header_deserialized));
                } else
                    LogPrintf("UDP: Got full header and shorttxids from %s\n", block.nodeHeaderRecvd.ToStringAddrPort());
            } else if (block.is_decodeable || block.block_data.IsBlockAvailable()) {
                if (block.currentlyProcessing) {
                    // We often duplicatively schedule DoBackgroundBlockProcessing,
                    // but we do not do anything to avoid duplicate
                    // final-processing. Thus, we have to check if we have already
                    // done final processing by checking currentlyProcessing (which
                    // is never un-set after we set it).
                    break;
                }
                block.currentlyProcessing = true;
                std::chrono::steady_clock::time_point reconstruct_start;
                if (fBench)
                    reconstruct_start = std::chrono::steady_clock::now();

                if (!block.block_data.IsBlockAvailable()) {
                    block.ReconstructBlockFromDecoder();
                    assert(block.block_data.IsBlockAvailable());
                }

                std::chrono::steady_clock::time_point fec_reconstruct_finished;
                if (fBench)
                    fec_reconstruct_finished = std::chrono::steady_clock::now();

                ReadStatus status = block.block_data.FinalizeBlock();

                std::chrono::steady_clock::time_point block_finalized;
                if (fBench)
                    block_finalized = std::chrono::steady_clock::now();

                if (status != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                    if (status == READ_STATUS_INVALID) {
                        if (process_block.first.second == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Unable to decode block from trusted peer(s), check your trusted peers are behaving well.\n");
                        else {
                            const auto it = mapUDPNodes.find(process_block.first.second);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    }
                    setBlocksReceived.insert(process_block.first);
                    RemovePartialBlock(process_block.first);
                    break;
                } else {
                    std::shared_ptr<const CBlock> pdecoded_block = block.block_data.GetBlock();
                    const CBlock& decoded_block = *pdecoded_block;
                    if (fBench) {
                        uint32_t total_chunks_recvd = 0, total_chunks_used = 0;
                        std::map<CService, std::pair<uint32_t, uint32_t>>& chunksProvidedByNode = block.nodesWithChunksAvailableSet;
                        for (const auto& provider : chunksProvidedByNode) {
                            total_chunks_recvd += provider.second.second;
                            total_chunks_used += provider.second.first;
                        }
                        LogPrintf("UDP: Block %s reconstructed from %s with %u chunks in %lf ms (%u recvd from %u peers)\n", decoded_block.GetHash().ToString(), block.nodeHeaderRecvd.ToStringAddrPort(), total_chunks_used, to_millis_double(std::chrono::steady_clock::now() - block.timeHeaderRecvd), total_chunks_recvd, chunksProvidedByNode.size());
                        for (const auto& provider : chunksProvidedByNode)
                            LogPrintf("UDP:    %u/%u used from %s\n", provider.second.first, provider.second.second, provider.first.ToStringAddrPort());
                    }

                    lock.unlock();

                    std::chrono::steady_clock::time_point process_start;
                    if (fBench)
                        process_start = std::chrono::steady_clock::now();

                    const bool force_requested = false;

                    bool fNewBlock;
                    // if (!ProcessNewBlock(Params(), pdecoded_block, false, &fNewBlock)) {
                    if (!chainman->ProcessNewBlock(pdecoded_block, force_requested, /*min_pow_checked=*/true, &fNewBlock)) {
                        bool have_prev;
                        {
                            LOCK(cs_main);
                            have_prev = chainman->BlockIndex().count(pdecoded_block->hashPrevBlock);
                        }
                        LogPrintf("UDP: Failed to decode block %s\n", decoded_block.GetHash().ToString());
                        std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                        if (have_prev) {
                            setBlocksReceived.insert(process_block.first);
                        } else {
                            // Allow re-downloading again later, useful for local backfill downloads
                            setBlocksReceived.erase(process_block.first);
                        }
                        RemovePartialBlock(process_block.first);
                        break; // Probably a tx collision generating merkle-tree errors
                    }
                    if (fBench) {
                        LogPrintf("UDP: Final block processing for %s took %lf %lf %lf %lf ms (new: %d)\n", decoded_block.GetHash().ToString(), to_millis_double(fec_reconstruct_finished - reconstruct_start), to_millis_double(block_finalized - fec_reconstruct_finished), to_millis_double(process_start - block_finalized), to_millis_double(std::chrono::steady_clock::now() - process_start), fNewBlock);
                        if (fNewBlock) {
                            size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(decoded_block));
                            LogPrintf("UDP: Block %s had serialized size %lu\n", decoded_block.GetHash().ToString(), block_size);
                        }
                    }

                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    setBlocksReceived.insert(process_block.first);
                    RemovePartialBlocks(process_block.first.first); // Ensure we remove even if we didnt UDPRelayBlock()
                }
            } else if (!block.in_header && block.initialized) {
                uint32_t mempool_provided_chunks = 0;
                uint32_t total_chunk_count = 0;
                uint256 blockHash;
                bool fDone = block.block_data.IsIterativeFillDone();
                while (!fDone) {
                    size_t firstChunkProcessed;
                    if (!lock)
                        lock.lock();
                    if (!total_chunk_count) {
                        total_chunk_count = block.block_data.GetChunkCount();
                        blockHash = block.block_data.GetBlockHash();
                    }
                    ReadStatus res = block.block_data.DoIterativeFill(firstChunkProcessed);
                    if (res != READ_STATUS_OK) {
                        lock.unlock();
                        std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                        if (res == READ_STATUS_INVALID) {
                            if (process_block.first.second == TRUSTED_PEER_DUMMY)
                                LogPrintf("UDP: Unable to process mempool for block %s from trusted peer(s), check your trusted peers are behaving well.\n", blockHash.ToString());
                            else {
                                LogPrintf("UDP: Unable to process mempool for block %s from %s, disconnecting\n", blockHash.ToString(), process_block.first.second.ToStringAddrPort());
                                const auto it = mapUDPNodes.find(process_block.first.second);
                                if (it != mapUDPNodes.end())
                                    DisconnectNode(it);
                            }
                        } else
                            LogPrintf("UDP: Unable to process mempool for block %s, dropping block\n", blockHash.ToString());
                        setBlocksReceived.insert(process_block.first);
                        RemovePartialBlock(process_block.first);
                        break;
                    } else {
                        while (firstChunkProcessed < total_chunk_count && block.block_data.IsChunkAvailable(firstChunkProcessed)) {
                            if (!block.decoder.HasChunk(firstChunkProcessed)) {
                                block.decoder.ProvideChunk(block.block_data.GetChunk(firstChunkProcessed), firstChunkProcessed);
                                mempool_provided_chunks++;
                            }
                            firstChunkProcessed++;
                        }

                        if (block.decoder.DecodeReady() || block.block_data.IsBlockAvailable()) {
                            block.is_decodeable = true;
                            more_work = true;
                            break;
                        }
                    }
                    fDone = block.block_data.IsIterativeFillDone();
                    if (!fDone && block.packet_awaiting_lock.load(std::memory_order_acquire)) {
                        lock.unlock();
                        std::this_thread::yield();
                    }
                }
                if (lock && !more_work)
                    lock.unlock();
                LogPrintf("UDP: Initialized block %s with %ld/%ld mempool-provided chunks (or more)\n", blockHash.ToString(), mempool_provided_chunks, total_chunk_count);
            }
        } while (more_work);
    }
}

void BlockRecvInit(ChainstateManager* chainman, PeerManager* peer_manager)
{
    process_block_thread.reset(new std::thread(&util::TraceThread, "udpprocess", std::function<void()>(std::bind(&ProcessBlockThread, chainman, peer_manager))));
}

void BlockRecvShutdown() {
    if (process_block_thread) {
        block_process_shutdown = true;
        block_process_cv.notify_all();
        process_block_thread->join();
        process_block_thread.reset();
    }
}

ReadStatus PartialBlockData::ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txn) {
    assert(in_header);
    in_header = false;
    initialized = false;
    return block_data.InitData(header, extra_txn);
}

bool PartialBlockData::Init(const UDPMessage& msg) {
    assert((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS);
    obj_length  = msg.msg.block.obj_length;
    if (obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR)
        return false;
    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER)
        data_recvd.resize(DIV_CEIL(obj_length, sizeof(UDPBlockMessage::data)) * sizeof(UDPBlockMessage::data));
    decoder = FECDecoder(obj_length);
    initialized = true;
    return true;
}

PartialBlockData::PartialBlockData(const CService& node, CTxMemPool* mempool, const UDPMessage& msg, const std::chrono::steady_clock::time_point& packet_recv) :
        timeHeaderRecvd(packet_recv), nodeHeaderRecvd(node),
        in_header(true), initialized(false),
        is_decodeable(false), is_header_processing(false),
        currentlyProcessing(false), block_data(mempool)
    { assert(Init(msg)); }

    void PartialBlockData::ReconstructBlockFromDecoder() {
        assert(decoder.DecodeReady());
    
        // Use the actual chunk count from block_data, not obj_length
        uint32_t chunk_count = block_data.GetChunkCount();
        
        for (uint32_t i = 0; i < chunk_count; i++) {
            if (!block_data.IsChunkAvailable(i)) {
                // Only copy if the decoder has this chunk
                if (i < DIV_CEIL(obj_length, sizeof(UDPBlockMessage::data))) {
                    const void* data_ptr = decoder.GetDataPtr(i);
                    assert(data_ptr);
                    memcpy(block_data.GetChunk(i), data_ptr, sizeof(UDPBlockMessage::data));
                } else {
                    // For chunks beyond what the decoder has, zero them out
                    // This handles the padding at the end of the block
                    memset(block_data.GetChunk(i), 0, FEC_CHUNK_SIZE);
                }
                block_data.MarkChunkAvailable(i);
            }
        }
    
        assert(block_data.IsBlockAvailable());
    }

static void BlockMsgHToLE(UDPMessage& msg) {
    msg.msg.block.hash_prefix = htole64_internal(msg.msg.block.hash_prefix);
    msg.msg.block.obj_length  = htole32_internal(msg.msg.block.obj_length);
    msg.msg.block.chunk_id    = htole32_internal(msg.msg.block.chunk_id);
}

static bool HandleTx(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const node::NodeContext* const node_context) {
    if (msg.msg.block.obj_length > 400000) {
        LogPrintf("UDP: Got massive tx obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    if (state.tx_in_flight_hash_prefix != msg.msg.block.hash_prefix) {
        state.tx_in_flight_hash_prefix = msg.msg.block.hash_prefix;
        state.tx_in_flight_msg_size    = msg.msg.block.obj_length;
        state.tx_in_flight.reset(new FECDecoder(msg.msg.block.obj_length));
    }

    if (!state.tx_in_flight) return true; // Already finished decode

    if (state.tx_in_flight_msg_size != msg.msg.block.obj_length) {
        LogPrintf("UDP: Got inconsistent object length for tx %lu\n", msg.msg.block.hash_prefix);
        return true;
    }

    assert(!state.tx_in_flight->DecodeReady());

    if (!state.tx_in_flight->ProvideChunk(msg.msg.block.data, msg.msg.block.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from tx %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    if (state.tx_in_flight->DecodeReady()) {
        std::vector<unsigned char> tx_data(msg.msg.block.obj_length);

        for (size_t i = 0; i < DIV_CEIL(tx_data.size(), FEC_CHUNK_SIZE); i++) {
            const void* chunk = state.tx_in_flight->GetDataPtr(i);
            assert(chunk);
            memcpy(tx_data.data() + i * FEC_CHUNK_SIZE, chunk, std::min(tx_data.size() - i * FEC_CHUNK_SIZE, (size_t)FEC_CHUNK_SIZE));
        }

        try {
            VectorInputStream stream(&tx_data);
            CTransactionRef tx;
            stream >>  TX_WITH_WITNESS(tx);
            LOCK(cs_main);
            TxValidationState state;
            const MempoolAcceptResult result = AcceptToMemoryPool(node_context->chainman->ActiveChainstate(), tx, GetTime(), /*bypass_limits=*/false, /*test_accept=*/false);
            if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                node_context->peerman->RelayTransaction(tx->GetHash(), tx->GetWitnessHash());
            }
        } catch (std::ios_base::failure& e) {
            LogPrintf("UDP: Tx decode failed for tx %lu from %s\n", msg.msg.block.hash_prefix, node.ToStringAddrPort());
            return true;
        }

        state.tx_in_flight.reset();
    }

    return true;
}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const node::NodeContext* const node_context) {
    //TODO: There are way too many damn tree lookups here...either cut them down or increase parallelism
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    assert((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS || (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS);

    if (length != sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage)) {
        LogPrintf("UDP: Got invalidly-sized block message from %s\n", node.ToStringAddrPort());
        return false;
    }

    msg.msg.block.hash_prefix = le64toh_internal(msg.msg.block.hash_prefix);
    msg.msg.block.obj_length  = le32toh_internal(msg.msg.block.obj_length);
    msg.msg.block.chunk_id    = le32toh_internal(msg.msg.block.chunk_id);

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS)
        return HandleTx(msg, length, node, state, node_context);

    const uint64_t hash_prefix = msg.msg.block.hash_prefix; // Need a reference in a few places, but its packed, so we can't have one directly
    const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node);

    if (msg.msg.block.obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR) {
        LogPrintf("UDP: Got massive obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    if (setBlocksRelayed.count(msg.msg.block.hash_prefix) || setBlocksReceived.count(hash_peer_pair))
        return true;

    std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = state.chunks_avail.find(msg.msg.block.hash_prefix);

    if (chunks_avail_it == state.chunks_avail.end()) {
        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER) {
            if (state.chunks_avail.size() > 1 && !state.connection.fTrusted) {
                // Non-trusted nodes can only be forwarding up to 2 blocks at a time
                assert(state.chunks_avail.size() == 2);
                auto first_partial_block_it  = mapPartialBlocks.find(std::make_pair(state.chunks_avail.begin()->first, node));
                assert(first_partial_block_it != mapPartialBlocks.end());
                auto second_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.rbegin()->first, node));
                assert(second_partial_block_it != mapPartialBlocks.end());
                if (first_partial_block_it->second->timeHeaderRecvd < second_partial_block_it->second->timeHeaderRecvd) {
                    state.chunks_avail.erase(first_partial_block_it->first.first);
                    mapPartialBlocks.erase(first_partial_block_it);
                } else {
                    state.chunks_avail.erase(second_partial_block_it->first.first);
                    mapPartialBlocks.erase(second_partial_block_it);
                }
            }
            // Once we add to chunks_avail, we MUST add to mapPartialBlocks->second->nodesWithChunksAvailableSet, or we will leak memory
            bool they_have_block = msg.header.msg_type & HAVE_BLOCK;
            size_t header_data_chunks = DIV_CEIL(msg.msg.block.obj_length, sizeof(UDPBlockMessage::data));
            chunks_avail_it = state.chunks_avail.emplace(std::piecewise_construct,
                                                         std::forward_as_tuple(hash_prefix),
                                                         std::forward_as_tuple(they_have_block, header_data_chunks)
                                                ).first;
        } else // Probably stale (ie we just finished reconstructing)
            return true;
    }

    if (msg.header.msg_type & HAVE_BLOCK)
        chunks_avail_it->second.SetAllAvailable();
    else {
        // By calling Set*ChunkAvailable before SendMessageToNode's
        // SetHeaderDataAndFECChunkCount call, we will miss the first block packet we
        // receive and re-send that in UDPRelayBlock...this is OK because we'll save
        // more by doing this before the during-process relay below
        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(msg.msg.block.chunk_id);
        else {
            if (!chunks_avail_it->second.IsBlockDataChunkCountSet())
                chunks_avail_it->second.SetBlockDataChunkCount(DIV_CEIL(msg.msg.block.obj_length, sizeof(UDPBlockMessage::data)));
            chunks_avail_it->second.SetBlockChunkAvailable(msg.msg.block.chunk_id);
        }
    }

    bool new_block = false;
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it = mapPartialBlocks.find(hash_peer_pair);
    if (it == mapPartialBlocks.end()) {
        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER)
            it = mapPartialBlocks.insert(std::make_pair(std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node), std::make_shared<PartialBlockData>(node, node_context->mempool.get(), msg, packet_process_start))).first;
        else // Probably stale (ie we just finished reconstructing)
            return true;
        new_block = true;
    }
    PartialBlockData& block = *it->second;

    std::chrono::steady_clock::time_point maps_scanned;
    if (fBench)
        maps_scanned = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> block_lock(block.state_mutex, std::try_to_lock);

    if (block.is_decodeable || block.currentlyProcessing || block.is_header_processing ||
        ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER && !block.in_header)) {
        // It takes quite some time to decode the block.
        // Further, its good to check some things like if this packet is for
        // header after we've gotten the header to avoid taking the block_lock
        // and possibly interrupting background fill.
        // Thus, while the block is processing in ProcessNewBlockThread, we
        // continue forwarding chunks we received from trusted peers
        // Note that we will also drop block body packets here while processing
        // the header, sadly isnt much we can do about that (unless we were to
        // queue them, but most of the packets we'll drop here are header FEC
        // anyway, so not much use in doing so).
        if (state.connection.fTrusted) {
            BlockMsgHToLE(msg);
            if (block.is_decodeable || block.currentlyProcessing)
                msg.header.msg_type |= HAVE_BLOCK;
            else
                msg.header.msg_type &= ~HAVE_BLOCK;
            // We didn't need this chunk, call it low priority assuming our
            // peers didn't as well
            SendMessageToAllNodes(msg, length, false, hash_prefix);
        }
        return true;
    }

    if (!block_lock) {
        block.packet_awaiting_lock.store(true, std::memory_order_release);
        block_lock.lock();
        block.packet_awaiting_lock.store(false, std::memory_order_release);
    }

    // is_decodeable || is_headerProcessing must come before any chunk-accessors in block.block_data
    if (block.is_decodeable || block.currentlyProcessing || block.is_header_processing)
        return true;

    std::map<CService, std::pair<uint32_t, uint32_t>>::iterator usefulChunksFromNodeIt =
            block.nodesWithChunksAvailableSet.insert(std::make_pair(node, std::make_pair(0, 0))).first;
    usefulChunksFromNodeIt->second.second++;

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER && !block.in_header) {
        if (state.connection.fTrusted) {
            // Keep forwarding on header packets to our peers to make sure they
            // get the whole header.
            BlockMsgHToLE(msg);
            msg.header.msg_type &= ~HAVE_BLOCK;
            // We didn't need this chunk, call it low priority assuming our
            // peers didn't as well
            SendMessageToAllNodes(msg, length, false, hash_prefix);
        }
        return true;
    }
    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS && block.in_header) {
        // Either we're getting packets out of order and wasting this packet,
        // or we didnt get enough header and will fail download anyway
        return true;
    }

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS && !block.initialized) {
        if (!block.Init(msg)) {
            LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", msg.msg.block.hash_prefix);
            return true;
        }
        DoBackgroundBlockProcessing(*it); // Kick off mempool scan (waits on us to unlock block_lock)
    }

    if (msg.msg.block.obj_length  != block.obj_length) {
        // Duplicate hash_prefix or bad trusted peer
        LogPrintf("UDP: Got wrong obj_length/chunsk_sent for block id %lu from peer %s! Check your trusted peers are behaving well\n", msg.msg.block.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    if (block.decoder.HasChunk(msg.msg.block.chunk_id))
        return true;

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS &&
            msg.msg.block.chunk_id < block.block_data.GetChunkCount()) {
        assert(!block.block_data.IsChunkAvailable(msg.msg.block.chunk_id)); // HasChunk should have returned false, then
        memcpy(block.block_data.GetChunk(msg.msg.block.chunk_id), msg.msg.block.data, sizeof(UDPBlockMessage::data));
        block.block_data.MarkChunkAvailable(msg.msg.block.chunk_id);
    }
    //TODO: Also pre-copy header data into data_recvd here, if its a non-FEC chunk

    if (!block.decoder.ProvideChunk(msg.msg.block.data, msg.msg.block.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from block %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    std::chrono::steady_clock::time_point chunks_processed;
    if (fBench)
        chunks_processed = std::chrono::steady_clock::now();

    usefulChunksFromNodeIt->second.first++;

    if (state.connection.fTrusted) {
        BlockMsgHToLE(msg);
        msg.header.msg_type &= ~HAVE_BLOCK;
        // We needed this chunk, call it high priority assuming our
        // peers will as well
        SendMessageToAllNodes(msg, length, true, hash_prefix);
    }

    if (block.decoder.DecodeReady()) {
        if (block.in_header)
            block.is_header_processing = true;
        else
            block.is_decodeable = true;

        // We do not RemovePartialBlock as we want ChunkAvailableSets to be there when UDPRelayBlock gets called
        // from inside ProcessBlockThread, so after we notify the ProcessNewBlockThread we cannot access block.
        block_lock.unlock();
        DoBackgroundBlockProcessing(*it); // Decode block and call ProcessNewBlock

        if (block.is_decodeable) {
            // Make sure we throw out any future packets for this block
            setBlocksReceived.insert(hash_peer_pair);
        }
    }

    if (fBench && new_block) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("UDP: Processed first block header chunk in %lf %lf %lf %lf\n", to_millis_double(start - packet_process_start), to_millis_double(maps_scanned - start), to_millis_double(chunks_processed - maps_scanned), to_millis_double(finished - chunks_processed));
    }

    return true;
}

void ProcessDownloadTimerEvents() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapPartialBlocks.begin(); it != mapPartialBlocks.end();) {
        if (to_millis_double(std::chrono::steady_clock::now() - it->second->timeHeaderRecvd) > 1000 * 60 * 60 * 24) // 1 day
            it = RemovePartialBlock(it);
        else
            it++;
    }
    //TODO: Prune setBlocksRelayed and setBlocksReceived to keep lookups fast?
}
