#pragma once
#include "defines.h"
#include "utils.h"
#include <cstddef>
#include <cstring>

struct RequestResponseHeader {
private:
    uint8_t _size[3];
    uint8_t _type;
    unsigned int _dejavu;

public:
    static constexpr unsigned int max_size = 0xFFFFFF;
    inline unsigned int size() {
        if (((*((unsigned int*)_size)) & 0xFFFFFF)==0) return INT32_MAX; // size is never zero, zero means broken packets
        return (*((unsigned int*)_size)) & 0xFFFFFF;
    }

    inline void setSize(unsigned int size) {
        _size[0] = (uint8_t)size;
        _size[1] = (uint8_t)(size >> 8);
        _size[2] = (uint8_t)(size >> 16);
    }

    inline bool isDejavuZero()
    {
        return !_dejavu;
    }

    inline void zeroDejavu()
    {
        _dejavu = 0;
    }

    inline void randomizeDejavu()
    {
        rand32(&_dejavu);
        if (!_dejavu)
        {
            _dejavu = 1;
        }
    }

    inline uint8_t type()
    {
        return _type;
    }

    inline void setType(const uint8_t type)
    {
        _type = type;
    }
};
typedef struct
{
    unsigned char sourcePublicKey[32];
    unsigned char destinationPublicKey[32];
    long long amount;
    unsigned int tick;
    unsigned short inputType;
    unsigned short inputSize;
} Transaction;

typedef struct
{
    unsigned short tickDuration;
    unsigned short epoch;
    unsigned int tick;
    unsigned short numberOfAlignedVotes;
    unsigned short numberOfMisalignedVotes;
    unsigned int initialTick;
} CurrentTickInfo;

struct TickData
{
    unsigned short computorIndex;
    unsigned short epoch;
    unsigned int tick;

    unsigned short millisecond;
    unsigned char second;
    unsigned char minute;
    unsigned char hour;
    unsigned char day;
    unsigned char month;
    unsigned char year;

    unsigned char timelock[32];
    unsigned char transactionDigests[NUMBER_OF_TRANSACTIONS_PER_TICK][32];
    long long contractFees[1024];

    unsigned char signature[SIGNATURE_SIZE];
    static constexpr unsigned char type()
    {
        return 8;
    }
};

typedef struct
{
    unsigned int tick;
} RequestedTickData;

typedef struct
{
    RequestedTickData requestedTickData;
    enum {
        type = 16,
    };
} RequestTickData;

typedef struct
{
    unsigned int tick;
    unsigned char voteFlags[(676 + 7) / 8];
    enum {
        type = 14,
    };
} RequestedQuorumTick;

typedef struct
{
    unsigned int tick;
    unsigned char transactionFlags[NUMBER_OF_TRANSACTIONS_PER_TICK / 8];
} RequestedTickTransactions;

typedef struct
{
    uint8_t sig[SIGNATURE_SIZE];
} SignatureStruct;
typedef struct
{
    char hash[60];
} TxhashStruct;
typedef struct
{
    std::vector<uint8_t> vecU8;
} extraDataStruct;

struct RequestLog // Fetches log
{
    unsigned long long passcode[4];
    unsigned long long fromid;
    unsigned long long toid;

    static constexpr unsigned char type()
    {
        return 44;
    }
};

struct RequestLogIdRange // Fetches logId range
{
    unsigned long long passcode[4];
    unsigned int tick;
    unsigned int txId;

    static constexpr unsigned char type()
    {
        return 48;
    }
};
struct ResponseLogIdRange // Fetches logId range
{
    long long fromLogId;
    long long length;

    static constexpr unsigned char type()
    {
        return 49;
    }
};

// Request logid ranges of all txs from a tick
struct RequestAllLogIdRangesFromTick
{
    unsigned long long passcode[4];
    unsigned int tick;

    static constexpr unsigned char type()
    {
        return 50;
    }
};

#define LOG_TX_NUMBER_OF_SPECIAL_EVENT 5
#define LOG_TX_PER_TICK (NUMBER_OF_TRANSACTIONS_PER_TICK + LOG_TX_NUMBER_OF_SPECIAL_EVENT)// +5 special events
// Response logid ranges of all txs from a tick
struct ResponseAllLogIdRangesFromTick
{
    long long fromLogId[LOG_TX_PER_TICK];
    long long length[LOG_TX_PER_TICK];

    static constexpr unsigned char type()
    {
        return 51;
    }
};


struct RespondLog // Returns buffered log; clears the buffer; make sure you fetch log quickly enough, if the buffer is overflown log stops being written into it till the node restart
{
    // Variable-size log;

    static constexpr unsigned char type()
    {
        return 45;
    }
};

// Request logid ranges of all txs from a tick
struct RequestPruningPageFiles
{
    unsigned long long passcode[4];
    unsigned long long fromLogId;
    unsigned long long toLogId;

    static constexpr unsigned char type()
    {
        return 56;
    }
};

// Response 0 if success, otherwise error code will be returned
struct ResponsePruningPageFiles
{
    long long success;
    static constexpr unsigned char type()
    {
        return 57;
    }
};

// Request logid ranges of all txs from a tick
struct RequestLogStateDigest
{
    unsigned long long passcode[4];
    unsigned int requestedTick;

    static constexpr unsigned char type()
    {
        return 58;
    }
};

// Response 0 if success, otherwise error code will be returned
struct ResponseLogStateDigest
{
    unsigned char digest[32];
    static constexpr unsigned char type()
    {
        return 59;
    }
};