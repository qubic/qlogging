#include <thread>
#include <chrono>
#include "stdio.h"
#include "connection.h"
#include "parser.h"
#include "structs.h"
#include "keyUtils.h"
#include "K12AndKeyUtil.h"
#include "logger.h"
#include <stdexcept>

#define ARBITRATOR "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ"
#define MAX_LOG_EVENT_PER_CALL 100000
#define RELAX_PER_CALL 0 //time to sleep between every call
#define REPORT_DIGEST_INTERVAL 10 // ticks
#define PRUNE_FILES_INTERVAL 0xFFFFFFFFFFFFFFFFULL // should be 30000000 to match core
#define DEBUG 0
#define SLEEP(x) std::this_thread::sleep_for(std::chrono::milliseconds(x))
static uint64_t gLastProcessedLogId = UINT64_MAX;
long long gTotalFetchedLog = 30000000;
long long gByteReceived = 0;
template<typename T>
T charToNumber(char *a) {
    T retVal = 0;
    char *endptr = nullptr;
    retVal = T(strtoull(a, &endptr, 10));
    return retVal;
}
static void printDebug(const char *fmt, ...)
{
#if DEBUG
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
#endif
}

void getTickData(QCPtr &qc, const uint32_t tick, TickData &result) {
    memset(&result, 0, sizeof(TickData));
    static struct {
        RequestResponseHeader header;
        RequestTickData requestTickData;
    } packet;
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(REQUEST_TICK_DATA);
    packet.requestTickData.requestedTickData.tick = tick;
    qc->sendData((uint8_t *) &packet, packet.header.size());
    result = qc->receivePacketAs<TickData>();
    return;
}

bool getLogFromNodeChunk(QCPtr &qc, uint64_t *passcode, uint64_t fromId, uint64_t toId) {
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        unsigned long long fromid;
        unsigned long long toid;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestLog::type());
    memcpy(packet.passcode, passcode, 4 * sizeof(uint64_t));
    packet.fromid = fromId;
    packet.toid = toId;
    qc->sendData((uint8_t *) &packet, packet.header.size());
    std::vector<uint8_t> buffer;
    qc->receiveAFullPacket(buffer);
    uint8_t *data = buffer.data();
    auto recvByte = buffer.size();
    int ptr = 0;
    uint64_t retLogId = -1; // max uint64
    while (ptr < recvByte) {
        auto header = (RequestResponseHeader *) (data + ptr);
        if (header->type() == RespondLog::type()) {
            auto logBuffer = (uint8_t *) (data + ptr + sizeof(RequestResponseHeader));
            retLogId = printQubicLog(logBuffer, header->size() - sizeof(RequestResponseHeader), fromId, toId);
            gByteReceived += header->size();
            if (retLogId == -1)
            {
                break;
            }
            gLastProcessedLogId = std::max(gLastProcessedLogId, retLogId);
            fflush(stdout);
        }
        ptr += header->size();
    }

    if (retLogId < toId) {
        LOG("[0] WARNING: Node doesn't return full data\n");
        return false;
    }
    if (retLogId == -1) {
        LOG("[1] WARNING: Unexpected value for retLogId (-1)\n");
        return false;
    }
    return true;
}

bool getLogFromNode(QCPtr &qc, uint64_t *passcode, uint64_t fromId, uint64_t toId)
{
    int retry = 0;
    bool finish = getLogFromNodeChunk(qc, passcode, fromId, toId);
    while (!finish && retry++ < 5)
    {
        SLEEP(1000);
        LOG("Failed to get logging content, retry in 1 second...\n");
        fromId = std::max(gLastProcessedLogId + 1, fromId);
        finish = getLogFromNodeChunk(qc, passcode, fromId, toId);
    }
    return finish;
}

void requestToPrune(QCPtr& qc, uint64_t* passcode, uint64_t requestedLogId) {
    struct {
        RequestResponseHeader header;
        RequestPruningPageFiles rppf;
    } packet;
    LOG("Calling to prune files from 0 to %llu...\n", requestedLogId);
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestPruningPageFiles::type());
    memcpy(packet.rppf.passcode, passcode, 4 * sizeof(uint64_t));
    packet.rppf.fromLogId = 0;
    packet.rppf.toLogId = requestedLogId;
    qc->sendData((uint8_t*)&packet, packet.header.size());
    auto result = qc->receivePacketAs<ResponsePruningPageFiles>();
    if (result.success != 0)
    {
        LOG("Failed to prune files, return code %d\n", result.success);
    }
    else
    {
        LOG("Successfully delete log file from 0 to %llu...\n", requestedLogId);
    }
}

bool getLogFromNodeLargeBatch(QCPtr &qc, uint64_t *passcode, uint64_t start, uint64_t end)
{
    if (gLastProcessedLogId == UINT64_MAX)
    {
        gLastProcessedLogId = 0;
    }
    else
    {
        start = std::max(gLastProcessedLogId + 1, start);
    }
    for (uint64_t s = start; s <= end; s += MAX_LOG_EVENT_PER_CALL)
    {
        uint64_t e = std::min(end, s + MAX_LOG_EVENT_PER_CALL - 1);
        if (!getLogFromNode(qc, passcode, s, e)) return false;
        SLEEP(RELAX_PER_CALL);
        gTotalFetchedLog += (e - s + 1); // inclusive
        if (gTotalFetchedLog >= PRUNE_FILES_INTERVAL)
        {
            requestToPrune(qc, passcode, e);
            gTotalFetchedLog = 0;
        }
    }
    return true;
}

void getLogIdRange(QCPtr &qc, uint64_t *passcode, uint32_t requestedTick, uint32_t txsId, long long &fromId,
                   long long &toId) {
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        unsigned int tick;
        unsigned int txId;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestLogIdRange::type());
    memcpy(packet.passcode, passcode, 4 * sizeof(uint64_t));
    packet.tick = requestedTick;
    packet.txId = txsId;
    qc->sendData((uint8_t *) &packet, packet.header.size());
    auto result = qc->receivePacketAs<ResponseLogIdRange>();
    if (result.length != -1) {
        fromId = result.fromLogId;
        toId = fromId + result.length - 1;
    } else {
        fromId = -1;
        toId = -1;
    }
}

ResponseAllLogIdRangesFromTick getAllLogIdRangesFromTick(QCPtr &qc, uint64_t *passcode, uint32_t requestedTick) {
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        unsigned int tick;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestAllLogIdRangesFromTick::type());
    memcpy(packet.passcode, passcode, 4 * sizeof(uint64_t));
    packet.tick = requestedTick;
    qc->sendData((uint8_t *) &packet, packet.header.size());
    auto result = qc->receivePacketAs<ResponseAllLogIdRangesFromTick>();
    return result;
}

// failed internet
bool isZero(ResponseAllLogIdRangesFromTick& resp)
{
    for (int i = 0; i < LOG_TX_PER_TICK; i++)
    {
        if (resp.fromLogId[i] != 0 || resp.length[i] != 0)
        {
            return false;
        }
    }
    return true;
}

// doesn't have log
bool isEmpty(ResponseAllLogIdRangesFromTick& resp)
{
    for (int i = 0; i < LOG_TX_PER_TICK; i++)
    {
        if (resp.fromLogId[i] != -1 || resp.length[i] != -1)
        {
            return false;
        }
    }
    return true;
}

// unknown because node is loaded from snapshot
bool isUnknown(ResponseAllLogIdRangesFromTick& resp)
{
    for (int i = 0; i < LOG_TX_PER_TICK; i++)
    {
        if (resp.fromLogId[i] != -2 || resp.length[i] != -2)
        {
            return false;
        }
    }
    return true;
}

// not yet generated because querying future tick or current tick is being processed
bool isNotYetGenerated(ResponseAllLogIdRangesFromTick& resp)
{
    for (int i = 0; i < LOG_TX_PER_TICK; i++)
    {
        if (resp.fromLogId[i] != -3 || resp.length[i] != -3)
        {
            return false;
        }
    }
    return true;
}

void getLogStateDigest(QCPtr& qc, uint64_t* passcode, uint32_t requestedTick, unsigned char out[32]) {
    struct {
        RequestResponseHeader header;
        RequestLogStateDigest rlsd;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestLogStateDigest::type());
    memcpy(packet.rlsd.passcode, passcode, 4 * sizeof(uint64_t));
    packet.rlsd.requestedTick = requestedTick;
    qc->sendData((uint8_t*)&packet, packet.header.size());
    auto result = qc->receivePacketAs<ResponseLogStateDigest>();
    memcpy(out, result.digest, 32);
}

static CurrentTickInfo getTickInfoFromNode(QCPtr &qc) {
    CurrentTickInfo result;
    memset(&result, 0, sizeof(CurrentTickInfo));
    struct {
        RequestResponseHeader header;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(REQUEST_CURRENT_TICK_INFO);
    qc->sendData((uint8_t *) &packet, packet.header.size());
    std::vector<uint8_t> buffer;
    qc->receiveAFullPacket(buffer);
    uint8_t *data = buffer.data();
    auto recvByte = buffer.size();
    int ptr = 0;
    while (ptr < recvByte) {
        auto header = (RequestResponseHeader *) (data + ptr);
        if (header->type() == RESPOND_CURRENT_TICK_INFO) {
            auto curTickInfo = (CurrentTickInfo *) (data + ptr + sizeof(RequestResponseHeader));
            result = *curTickInfo;
        }
        ptr += header->size();
    }
    return result;
}
#if DEBUG
static void getTickTransactions(QCPtr &qc, const uint32_t requestedTick, int requestedTxId,
                                Transaction &txs, //out
                                extraDataStruct &extraData // out
) {
    struct {
        RequestResponseHeader header;
        RequestedTickTransactions txs;
    } packet;
    memset(&packet, 0, sizeof(packet));
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(REQUEST_TICK_TRANSACTIONS); // REQUEST_TICK_TRANSACTIONS
    packet.txs.tick = requestedTick;
    for (int i = 0; i < (1024 + 7) / 8; i++) packet.txs.transactionFlags[i] = 0xff;

    {
        packet.txs.transactionFlags[requestedTxId >> 3] &= ~(1 << (requestedTxId & 7));
    }
    qc->sendData((uint8_t *) &packet, packet.header.size());

    {
        std::vector<uint8_t> buffer;
        qc->receiveAFullPacket(buffer);
        uint8_t *data = buffer.data();
        int recvByte = int(buffer.size());
        int ptr = 0;
        while (ptr < recvByte) {
            auto header = (RequestResponseHeader *) (data + ptr);
            if (header->type() == BROADCAST_TRANSACTION) {
                auto tx = (Transaction *) (data + ptr + sizeof(RequestResponseHeader));
                txs = *tx;
                extraDataStruct ed;
                ed.vecU8.resize(tx->inputSize);
                if (tx->inputSize != 0) {
                    memcpy(ed.vecU8.data(), reinterpret_cast<const uint8_t *>(tx) + sizeof(Transaction), tx->inputSize);
                }
                extraData = ed;
            }
            ptr += header->size();
        }
    }
    {
        // receive END OF transmission
        std::vector<uint8_t> buffer;
        qc->receiveAFullPacket(buffer);
    }
}

void
printReceipt(Transaction &tx, const char *txHash = nullptr, const uint8_t *extraData = nullptr, int moneyFlew = -1) {
    char sourceIdentity[128] = {0};
    char dstIdentity[128] = {0};
    char txHashClean[128] = {0};
    bool isLowerCase = false;
    getIdentityFromPublicKey(tx.sourcePublicKey, sourceIdentity, isLowerCase);
    getIdentityFromPublicKey(tx.destinationPublicKey, dstIdentity, isLowerCase);
    LOG("~~~~~RECEIPT~~~~~\n");
    if (txHash != nullptr) {
        memcpy(txHashClean, txHash, 60);
        LOG("TxHash: %s\n", txHashClean);
    }
    LOG("From: %s\n", sourceIdentity);
    LOG("To: %s\n", dstIdentity);
    LOG("Input type: %u\n", tx.inputType);
    LOG("Amount: %lu\n", tx.amount);
    LOG("Tick: %u\n", tx.tick);
    LOG("Extra data size: %u\n", tx.inputSize);
    if (extraData != nullptr && tx.inputSize) {
        char hex_tring[1024 * 2] = {0};
        for (int i = 0; i < tx.inputSize; i++)
            sprintf(hex_tring + i * 2, "%02x", extraData[i]);

        LOG("Extra data: %s\n", hex_tring);
    }
    if (moneyFlew != -1) {
        if (moneyFlew) LOG("MoneyFlew: Yes\n");
        else LOG("MoneyFlew: No\n");
    } else {
        LOG("MoneyFlew: N/A\n");
    }
    LOG("~~~~~END-RECEIPT~~~~~\n");
}
#endif
uint32_t getTickNumberFromNode(QCPtr &qc) {
    auto curTickInfo = getTickInfoFromNode(qc);
    return curTickInfo.tick;
}
uint32_t getInitialTickFromNode(QCPtr &qc) {
    auto curTickInfo = getTickInfoFromNode(qc);
    return curTickInfo.initialTick;
}


unsigned int SC_INITIALIZE_TX = NUMBER_OF_TRANSACTIONS_PER_TICK + 0;
unsigned int SC_BEGIN_EPOCH_TX = NUMBER_OF_TRANSACTIONS_PER_TICK + 1;
unsigned int SC_BEGIN_TICK_TX = NUMBER_OF_TRANSACTIONS_PER_TICK + 2;
unsigned int SC_END_TICK_TX = NUMBER_OF_TRANSACTIONS_PER_TICK + 3;
unsigned int SC_END_EPOCH_TX = NUMBER_OF_TRANSACTIONS_PER_TICK + 4;

bool isValidRange(long long start, long long length)
{
    return start >= 0 && length > 0;
}

void printTxMapTable(ResponseAllLogIdRangesFromTick& txmap)
{
    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    LOG("Event\t\tFromId\tToId\n");
    if (isValidRange(txmap.fromLogId[SC_INITIALIZE_TX], txmap.length[SC_INITIALIZE_TX]))
    {
        LOG("SC_INIT\t\t%u\t%u\n", txmap.fromLogId[SC_INITIALIZE_TX], txmap.fromLogId[SC_INITIALIZE_TX] + txmap.length[SC_INITIALIZE_TX] - 1);
    }
    if (isValidRange(txmap.fromLogId[SC_BEGIN_EPOCH_TX], txmap.length[SC_BEGIN_EPOCH_TX]))
    {
        LOG("BEGIN_EPOCH\t\t%u\t%u\n", txmap.fromLogId[SC_BEGIN_EPOCH_TX], txmap.fromLogId[SC_BEGIN_EPOCH_TX] + txmap.length[SC_BEGIN_EPOCH_TX] - 1);
    }
    if (isValidRange(txmap.fromLogId[SC_BEGIN_TICK_TX], txmap.length[SC_BEGIN_TICK_TX]))
    {
        LOG("BEGIN_TICK\t\t%u\t%u\n", txmap.fromLogId[SC_BEGIN_TICK_TX], txmap.fromLogId[SC_BEGIN_TICK_TX] + txmap.length[SC_BEGIN_TICK_TX] - 1);
    }
    for (int i = 0; i < NUMBER_OF_TRANSACTIONS_PER_TICK; i++)
    {
        if (isValidRange(txmap.fromLogId[i], txmap.length[i]))
        {
            LOG("Tx #%d\t\t%u\t%u\n", i, txmap.fromLogId[i], txmap.fromLogId[i] + txmap.length[i] - 1);
        }
    }

    if (isValidRange(txmap.fromLogId[SC_END_TICK_TX], txmap.length[SC_END_TICK_TX]))
    {
        LOG("END_TICK\t\t%u\t%u\n", txmap.fromLogId[SC_END_TICK_TX], txmap.fromLogId[SC_END_TICK_TX] + txmap.length[SC_END_TICK_TX] - 1);
    }
    if (isValidRange(txmap.fromLogId[SC_END_EPOCH_TX], txmap.length[SC_END_EPOCH_TX]))
    {
        LOG("END_EPOCH\t\t%u\t%u\n", txmap.fromLogId[SC_END_EPOCH_TX], txmap.fromLogId[SC_END_EPOCH_TX] + txmap.length[SC_END_EPOCH_TX] - 1);
    }
    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

int run(int argc, char *argv[]) {
    if (argc < 8) {
        printf("./qlogging [nodeip] [nodeport] [passcode u64 x 4] [tick to start] [start logId (optional)] \n");
        return 0;
    }
    
    uint8_t arbPubkey[32];
    getPublicKeyFromIdentity(ARBITRATOR, arbPubkey);
    char *nodeIp = argv[1];
    int nodePort = charToNumber<int>(argv[2]);
    uint64_t passcode[4] = {charToNumber<unsigned long long>(argv[3]), charToNumber<unsigned long long>(argv[4]),
                            charToNumber<unsigned long long>(argv[5]), charToNumber<unsigned long long>(argv[6])};
    unsigned int tick = charToNumber<unsigned int>(argv[7]);
    if (argc >= 9) gLastProcessedLogId = charToNumber<unsigned int>(argv[8]);
    QCPtr qc;
    uint32_t currentTick = 0;
    bool needReconnect = true;
    int failedCount = 0;
    int maxFailedCount = 5;    
    unsigned int initTick = 0;
    
    while (1) {
        try {
            if (needReconnect) {
                qc = make_qc(nodeIp, nodePort);
                // do the handshake stuff
                std::vector<uint8_t> buff;
                qc->receiveAFullPacket(buff);
                needReconnect = false;
            }

            if (currentTick == 0 || currentTick <= tick) {
                if (currentTick == 0)
                {
                    initTick = getInitialTickFromNode(qc);
                    if (initTick != 0 && tick < initTick)
                    {
                        tick = initTick;
                        LOG("Requested tick is lower than initial tick of the node, force change tick => %u\n", initTick);
                    }
                }
                currentTick = getTickNumberFromNode(qc);
            }
            if (currentTick < tick) {
                printDebug("Current tick %u vs local tick %u | sleep 3s\n", currentTick, tick);
                SLEEP(3000);
                continue;
            }

            if ((tick - 2) % REPORT_DIGEST_INTERVAL == 0 && (tick - 2 >= initTick))
            {
                uint8_t logDigest[32] = { 0 };
                getLogStateDigest(qc, passcode, tick - 2, logDigest);
                if (!isArrayZero(logDigest, 32)) // log state digest is never zero
                {
                    LOG("Log digest at tick %d:", tick - 2);
                    for (int i = 0; i < 32; i++) printf("%02x", logDigest[i]); printf("\n");
                }
                else
                {
                    LOG("Failed to get log digest at tick %d - retry...\n", tick - 2);
                    SLEEP(3000);
                    continue;
                }
            }

            auto all_ranges = getAllLogIdRangesFromTick(qc, passcode, tick);
            bool is_zero = isZero(all_ranges);
            bool is_empty = isEmpty(all_ranges);
            bool is_unknown = isUnknown(all_ranges);
            bool is_not_yet_generated = isNotYetGenerated(all_ranges);
            if (is_zero)
            {
                if (failedCount++ >= maxFailedCount)
                {
                    LOG("Failed to receive data for tick %u\n", tick);
                    LOG("Reconnecting...\n");
                    failedCount = 0;
                    needReconnect = true;
                    SLEEP(3000);
                }
                SLEEP(1000);
                continue;
            }
            else
            {
                failedCount = 0;
            }
            if (is_empty || is_unknown)
            {
                if (is_empty) LOG("Tick %u doesn't generate any log\n", tick);
                if (is_unknown) LOG("This node doesn't have logging for tick %u\n", tick);
                tick++;
                continue;
            }
            if (is_not_yet_generated)
            {
                printDebug("Current tick %u vs local tick %u | sleep 3s\n", currentTick, tick);
                SLEEP(3000);
                continue;
            }

            long long fromId = INT64_MAX;
            long long toId = -1;
            for (int i = 0; i < LOG_TX_PER_TICK; i++)
            {
                if (isValidRange(all_ranges.fromLogId[i], all_ranges.length[i]))
                {
                    fromId = std::min(fromId, all_ranges.fromLogId[i]);
                    toId = std::max(toId, all_ranges.fromLogId[i] + all_ranges.length[i] - 1);
                }
            }

            if (fromId <= toId && fromId >= 0)
            {
                // print the txId <-> logId map table here
                printTxMapTable(all_ranges);
                if (!getLogFromNodeLargeBatch(qc, passcode, fromId, toId))
                {
                    LOG("Failed to get batch log [%llu -> %llu]. Retry in 10s\n", fromId, toId);
                    needReconnect = true;
                    SLEEP(1000);
                    continue;
                }
            }
            else
            {
                LOG("[DO NOT EXPECT HERE] Malformed data %u\n", tick);
            }
            tick++;
            
            fflush(stdout);
        }
        catch (std::logic_error &ex) {
            printf("%s\n", ex.what());
            fflush(stdout);
            needReconnect = true;
            SLEEP(3000);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    try {
        return run(argc, argv);
    }
    catch (std::exception &ex) {
        printf("%s\n", ex.what());
        return -1;
    }
}
