// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <assert.h>
#include <atomic>
#include <chain.h>
#include <mutex>
#include <stdint.h>
#include <vector>

#include <udpapi.h>

#include <blockencodings.h>
#include <fec.h>
#include <netaddress.h>

// This is largely the API between udpnet and udprelay, see udpapi for the
// external-facing API

// Local stuff only uses magic, net stuff only uses protocol_version,
// so both need to be changed any time wire format changes
static const unsigned char LOCAL_MAGIC_BYTES[] = { 0xab, 0xad, 0xca, 0xfe };
static const uint32_t UDP_PROTOCOL_VERSION = (4 << 16) | 4; // Min version 3, current version 3

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
    MSG_TYPE_TX_CONTENTS = 7,
};

static const uint8_t UDP_MSG_TYPE_FLAGS_MASK = 0b11000000;
static const uint8_t UDP_MSG_TYPE_TYPE_MASK = 0b00111111;

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1;
    uint64_t chk2;
    uint8_t msg_type; // A UDPMessageType + flags
};
static_assert(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1167 bytes (1185 bytes in total UDP message contents, with a padding byte in message)
// Local send logic assumes this to be the size of block data packets in a few places!
#define MAX_UDP_MESSAGE_LENGTH 1167

enum UDPBlockMessageFlags { // Put in the msg_type
    HAVE_BLOCK = (1 << 6),
};

struct __attribute__((packed)) UDPBlockMessage { // (also used for txn)
    /**
     * First 8 bytes of blockhash, interpreted in LE (note that this will not include 0s, those are at the end).
     * For txn, first 8 bytes of tx, though this should change in the future.
     * Neither block nor tx recv-side logic cares what this is as long as it mostly-uniquely identifies the
     * object being sent!
     */
    uint64_t hash_prefix;
    uint32_t obj_length; // Size of full FEC-coded data
    uint32_t chunk_id : 24;
    unsigned char data[FEC_CHUNK_SIZE];
};
static_assert(sizeof(UDPBlockMessage) == MAX_UDP_MESSAGE_LENGTH, "Messages must be == MAX_UDP_MESSAGE_LENGTH");

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
        struct UDPBlockMessage block;
    } msg;
};
static_assert(sizeof(UDPMessage) == 1185, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
static_assert(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
static_assert(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0, // Indicating the node was just added
    STATE_GOT_SYN = 1, // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1, // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
};

struct PartialBlockData {
    const std::chrono::steady_clock::time_point timeHeaderRecvd;
    const CService nodeHeaderRecvd;

    std::atomic_bool in_header; // Indicates we are currently downloading header (or block txn)
    std::atomic_bool initialized; // Indicates Init has been called in current in_header state
    std::atomic_bool is_decodeable; // Indicates decoder.DecodeReady() && !in_header
    std::atomic_bool is_header_processing; // Indicates in_header && !initialized but header is ready
    std::atomic_bool packet_awaiting_lock; // Indicates there is a packet ready to process that needs state_mutex

    std::mutex state_mutex;
    // Background thread is preparing to, and is submitting to core
    // This is set with state_mutex held, and afterwards block_data and
    // nodesWithChunksAvailableSet should be treated read-only.
    std::atomic_bool currentlyProcessing;

    uint32_t obj_length; // FEC-coded length of currently-being-download object
    std::vector<unsigned char> data_recvd; // Used for header data chunks, not FEC or block chunks
    FECDecoder decoder; // Note that this may have been std::move()d if (currentlyProcessing)
    PartiallyDownloadedChunkBlock block_data;

    // nodes with chunks_avail set -> packets that were useful, packets provided
    std::map<CService, std::pair<uint32_t, uint32_t> > nodesWithChunksAvailableSet;

    bool Init(const UDPMessage& msg);
    ReadStatus ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header, const std::vector<std::pair<Wtxid, CTransactionRef>>& extra_txn);
    PartialBlockData(const CService& node, CTxMemPool* mempool, const UDPMessage& header_msg, const std::chrono::steady_clock::time_point& packet_recv); // Must be a MSG_TYPE_BLOCK_HEADER
    void ReconstructBlockFromDecoder();
};

class ChunksAvailableSet {
private:
    bool allSent;
    bool block_tracker_initd;
    BlockChunkRecvdTracker header_tracker;
    BlockChunkRecvdTracker block_tracker;
public:
    ChunksAvailableSet(bool hasAllChunks, size_t header_chunks) :
            allSent(hasAllChunks), block_tracker_initd(false)
        { if (!allSent) header_tracker = BlockChunkRecvdTracker(header_chunks); }

    bool IsHeaderChunkAvailable(uint32_t chunk_id) const {
        if (allSent) return true;
        return header_tracker.CheckPresent(chunk_id);
    }
    void SetHeaderChunkAvailable(uint32_t chunk_id) {
        if (allSent) return;
        header_tracker.CheckPresentAndMarkRecvd(chunk_id);
    }

    bool IsBlockDataChunkCountSet() const { return block_tracker_initd; }
    void SetBlockDataChunkCount(size_t block_chunks) {
        block_tracker = BlockChunkRecvdTracker(block_chunks);
        block_tracker_initd = true;
    }

    bool IsBlockChunkAvailable(uint32_t chunk_id) const {
        if (allSent) return true;
        assert(block_tracker_initd);
        return block_tracker.CheckPresent(chunk_id);
    }
    void SetBlockChunkAvailable(uint32_t chunk_id) {
        if (allSent) return;
        assert(block_tracker_initd);
        block_tracker.CheckPresentAndMarkRecvd(chunk_id);
    }

    void SetAllAvailable() { allSent = true; }
    bool AreAllAvailable() const { return allSent; }
};

struct UDPConnectionInfo {
    uint64_t local_magic;  // Already LE
    uint64_t remote_magic; // Already LE
    size_t group;
    bool fTrusted;
    UDPConnectionType connection_type;
};

struct UDPConnectionState {
    UDPConnectionInfo connection;
    int state; // Flags from UDPState
    uint32_t protocolVersion;
    int64_t lastSendTime;
    int64_t lastRecvTime;
    int64_t lastPingTime;
    std::map<uint64_t, int64_t> ping_times;
    double last_pings[10];
    unsigned int last_ping_location;
    // for speed calculations (mbps)
    int64_t rcvdBytes;
    int64_t lastAvgTime;
    std::map<uint64_t, ChunksAvailableSet> chunks_avail;
    uint64_t tx_in_flight_hash_prefix, tx_in_flight_msg_size;
    std::unique_ptr<FECDecoder> tx_in_flight;

    UDPConnectionState() : connection({}), state(0), protocolVersion(0), lastSendTime(0), lastRecvTime(0), lastPingTime(0), last_ping_location(0),
        rcvdBytes(0), lastAvgTime(0), tx_in_flight_hash_prefix(0), tx_in_flight_msg_size(0)
        { for (size_t i = 0; i < sizeof(last_pings) / sizeof(double); i++) last_pings[i] = -1; }
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

extern std::recursive_mutex cs_mapUDPNodes;
extern std::map<CService, UDPConnectionState> mapUDPNodes;
extern std::atomic<uint64_t> min_per_node_mbps; // Used to determine header FEC chunk count
extern bool maybe_have_write_nodes;

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group);
void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::map<CService, UDPConnectionState>::const_iterator& node);
void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it);

#endif
