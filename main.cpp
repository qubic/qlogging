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
#define DEBUG 0

static uint64_t gLastProcessedLogId = 0;

template<typename T>
T charToNumber(char *a) {
    T retVal = 0;
    char *endptr = nullptr;
    retVal = strtoull(a, &endptr, 10);
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

void getLogFromNodeChunk(QCPtr &qc, uint64_t *passcode, uint64_t fromId, uint64_t toId) {
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
    int recvByte = buffer.size();
    int ptr = 0;
    unsigned long long retLogId = -1; // max uint64
    while (ptr < recvByte) {
        auto header = (RequestResponseHeader *) (data + ptr);
        if (header->type() == RespondLog::type()) {
            auto logBuffer = (uint8_t *) (data + ptr + sizeof(RequestResponseHeader));
            retLogId = printQubicLog(logBuffer, header->size() - sizeof(RequestResponseHeader));
            fflush(stdout);
        }
        ptr += header->size();
    }

    if (retLogId < toId) {
        // round buffer case, only the first half returned, call one more time to print out another half
        getLogFromNodeChunk(qc, passcode, retLogId + 1, toId);
    }
    if (retLogId == -1) {
        LOG("[0] WARNING: Unexpected value for retLogId\n");
    }
}

void getLogFromNodeOneByOne(QCPtr &qc, uint64_t *passcode, uint64_t _fromId, uint64_t _toId)
{
    struct {
        RequestResponseHeader header;
        unsigned long long passcode[4];
        unsigned long long fromid;
        unsigned long long toid;
    } packet;
    for (uint64_t l_id = _fromId; l_id <= _toId; l_id++)
    {
        if (l_id < gLastProcessedLogId) continue;
        memset(&packet, 0, sizeof(packet));
        packet.header.setSize(sizeof(packet));
        packet.header.randomizeDejavu();
        packet.header.setType(RequestLog::type());
        memcpy(packet.passcode, passcode, 4 * sizeof(uint64_t));
        packet.fromid = l_id;
        packet.toid = l_id;
        qc->sendData((uint8_t *) &packet, packet.header.size());
        std::vector<uint8_t> buffer;
        qc->receiveAFullPacket(buffer);
        uint8_t *data = buffer.data();
        int recvByte = buffer.size();
        int ptr = 0;
        unsigned long long retLogId = -1; // max uint64
        while (ptr < recvByte) {
            auto header = (RequestResponseHeader *) (data + ptr);
            if (header->type() == RespondLog::type()) {
                auto logBuffer = (uint8_t *) (data + ptr + sizeof(RequestResponseHeader));
                retLogId = printQubicLog(logBuffer, header->size() - sizeof(RequestResponseHeader));
                gLastProcessedLogId = retLogId;
                fflush(stdout);
            }
            ptr += header->size();
        }
        if (retLogId == -1) {
            LOG("[1] WARNING: Unexpected value for retLogId\n");
        }
    }
}

void getLogFromNode(QCPtr &qc, uint64_t *passcode, uint64_t fromId, uint64_t toId)
{
    getLogFromNodeChunk(qc, passcode, fromId, toId);
    //getLogFromNodeOneByOne(qc, passcode, fromId, toId);
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
    int recvByte = buffer.size();
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
        int recvByte = buffer.size();
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
uint32_t getTickNumberFromNode(QCPtr &qc, char *isFirstTick = NULL) {
    auto curTickInfo = getTickInfoFromNode(qc);
    if (isFirstTick) {
        *isFirstTick = curTickInfo.initialTick == curTickInfo.tick;
    }
    return curTickInfo.tick;
}

//TickData td;

void checkSystemLog(QCPtr &qc, uint64_t *passcode, unsigned int tick, unsigned int systemEventID,
                    std::string systemEventName) {
    long long fromId = 0, toId = 0;
    getLogIdRange(qc, passcode, tick, systemEventID, fromId, toId);
    if (fromId < 0 || toId < 0) {}
    else {
        printf("Tick %u %s has log from %lld to %lld\n", tick, systemEventName.c_str(), fromId, toId);
        getLogFromNode(qc, passcode, fromId, toId);
    }
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
        LOG("SC_INIT\t\t%u\t%u\n", txmap.fromLogId[SC_INITIALIZE_TX], txmap.fromLogId[SC_INITIALIZE_TX] + txmap.length[SC_INITIALIZE_TX]);
    }
    if (isValidRange(txmap.fromLogId[SC_BEGIN_EPOCH_TX], txmap.length[SC_BEGIN_EPOCH_TX]))
    {
        LOG("BEGIN_EPOCH\t\t%u\t%u\n", txmap.fromLogId[SC_BEGIN_EPOCH_TX], txmap.fromLogId[SC_BEGIN_EPOCH_TX] + txmap.length[SC_BEGIN_EPOCH_TX]);
    }
    if (isValidRange(txmap.fromLogId[SC_BEGIN_TICK_TX], txmap.length[SC_BEGIN_TICK_TX]))
    {
        LOG("BEGIN_TICK\t\t%u\t%u\n", txmap.fromLogId[SC_BEGIN_TICK_TX], txmap.fromLogId[SC_BEGIN_TICK_TX] + txmap.length[SC_BEGIN_TICK_TX]);
    }
    for (int i = 0; i < LOG_TX_PER_TICK; i++)
    {
        if (isValidRange(txmap.fromLogId[i], txmap.length[i]))
        {
            LOG("Tx #%d\t\t%u\t%u\n", i, txmap.fromLogId[i], txmap.fromLogId[i] + txmap.length[i]);
        }
    }

    if (isValidRange(txmap.fromLogId[SC_END_TICK_TX], txmap.length[SC_END_TICK_TX]))
    {
        LOG("END_TICK\t\t%u\t%u\n", txmap.fromLogId[SC_END_TICK_TX], txmap.fromLogId[SC_END_TICK_TX] + txmap.length[SC_END_TICK_TX]);
    }
    if (isValidRange(txmap.fromLogId[SC_END_EPOCH_TX], txmap.length[SC_END_EPOCH_TX]))
    {
        LOG("END_EPOCH\t\t%u\t%u\n", txmap.fromLogId[SC_END_EPOCH_TX], txmap.fromLogId[SC_END_EPOCH_TX] + txmap.length[SC_END_EPOCH_TX]);
    }
    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}


int run(int argc, char *argv[]) {
    if (argc != 8) {
        printf("./qlogging [nodeip] [nodeport] [passcode u64 x 4] [tick to start]\n");
        return 0;
    }
    uint8_t arbPubkey[32];
    getPublicKeyFromIdentity(ARBITRATOR, arbPubkey);
    char *nodeIp = argv[1];
    int nodePort = charToNumber<int>(argv[2]);
    uint64_t passcode[4] = {charToNumber<unsigned long long>(argv[3]), charToNumber<unsigned long long>(argv[4]),
                            charToNumber<unsigned long long>(argv[5]), charToNumber<unsigned long long>(argv[6])};
    unsigned int tick = charToNumber<unsigned int>(argv[7]);
    QCPtr qc;
    uint32_t currentTick = 0;
    bool needReconnect = true;
    char isFirstTick = 0;
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
                isFirstTick = 0;
                currentTick = getTickNumberFromNode(qc, &isFirstTick);
            }
            if (currentTick <= tick) {
                printDebug("Current tick %u vs local tick %u | sleep 3s\n", currentTick, tick);
                std::this_thread::sleep_for(std::chrono::seconds(3));
                continue;
            }
            //ResponseAllLogIdRangesFromTick getAllLogIdRangesFromTick(QCPtr &qc, uint64_t *passcode, uint32_t requestedTick) {
            auto all_ranges = getAllLogIdRangesFromTick(qc, passcode, tick);
            long long fromId = INT64_MAX;
            long long toId = -1;
            for (int i = 0; i < LOG_TX_PER_TICK; i++)
            {
                if (isValidRange(all_ranges.fromLogId[i], all_ranges.length[i]))
                {
                    fromId = std::min(fromId, all_ranges.fromLogId[i]);
                    toId = std::max(toId, all_ranges.fromLogId[i] + all_ranges.length[i]);
                }
            }
            if (fromId < toId && fromId >= 0 && toId > 0)
            {
                // print the txId <-> logId map table here
                printTxMapTable(all_ranges);
                getLogFromNode(qc, passcode, fromId, toId);
            }
            else
            {
                LOG("Tick %u doesn't generate any log\n", tick);
            }
            tick++;
            fflush(stdout);
        }
        catch (std::logic_error &ex) {
            printf("%s\n", ex.what());
            fflush(stdout);
            needReconnect = true;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
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
