#include "parser.h"
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "utils.h"
#include "keyUtils.h"
#include "logger.h"
#include "K12AndKeyUtil.h"

// 0 is short form, 1 is more details, 2 is all details
int parseToStringDetailLevel = 1;

#define QU_TRANSFER 0
#define QU_TRANSFER_LOG_SIZE 72
#define ASSET_ISSUANCE 1
#define ASSET_ISSUANCE_LOG_SIZE 63
#define ASSET_OWNERSHIP_CHANGE 2
#define ASSET_OWNERSHIP_CHANGE_LOG_SIZE 127
#define ASSET_POSSESSION_CHANGE 3
#define ASSET_POSSESSION_CHANGE_LOG_SIZE 127
#define CONTRACT_ERROR_MESSAGE 4
#define CONTRACT_ERROR_MESSAGE_LOG_SIZE 4
#define CONTRACT_WARNING_MESSAGE 5
#define CONTRACT_INFORMATION_MESSAGE 6
#define CONTRACT_DEBUG_MESSAGE 7
#define BURNING 8
#define BURNING_LOG_SIZE 44
#define DUST_BURNING 9
#define DUST_BURNING_MAX_LOG_SIZE 2621442
#define SPECTRUM_STATS 10
#define SPECTRUM_STATS_LOG_SIZE 224
#define CONTRACT_RESERVE_DEDUCTION 13
#define CONTRACT_RESERVE_DEDUCTION_LOG_SIZE 24
#define ORACLE_QUERY_STATUS_CHANGE 14
#define ORACLE_QUERY_STATUS_CHANGE_LOG_SIZE 46
#define ORACLE_SUBSCRIBER_MESSAGE 15
#define ORACLE_SUBSCRIBER_MESSAGE_LOG_SIZE 24
#define CUSTOM_MESSAGE 255

#define LOG_HEADER_SIZE 26 // 2 bytes epoch + 4 bytes tick + 4 bytes log size/types + 8 bytes log id + 8 bytes log digest

std::string logTypeToString(uint8_t type){
    switch(type){
        case 0:
            return "QU transfer";
        case 1:
            return "Asset issuance";
        case 2:
            return "Asset ownership change";
        case 3:
            return "Asset possession change";
        case 4:
            return "Contract error";
        case 5:
            return "Contract warning";
        case 6:
            return "Contract info";
        case 7:
            return "Contract debug";
        case 8:
            return "Burn";
        case 9:
            return "Dust burn";
        case 10:
            return "Spectrum stats";
        case 13:
            return "Contract reserve deduction";
        case ORACLE_QUERY_STATUS_CHANGE:
            return "Oracle query status change";
        case ORACLE_SUBSCRIBER_MESSAGE:
            return "Oracle subscriber change";
        case 255:
            return "Custom msg";
    }
    return "Unknown msg";
}
std::string parseLogToString_type0(uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char destIdentity[61] = {0};;
    uint64_t amount;
    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr+32, destIdentity, isLowerCase);
    memcpy(&amount, ptr+64, 8);
    std::string result = "from " + std::string(sourceIdentity) + " to " + std::string(destIdentity) + " " + std::to_string(amount) + "QU.";
    return result;
}
std::string parseLogToString_type1(uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char name[8] = {0};
    char numberOfDecimalPlaces = 0;
    uint8_t unit[8] = {0};

    long long numberOfShares = 0;
    long long managingIndex = 0;
    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    memcpy(&numberOfShares, ptr+32, 8);
    memcpy(&managingIndex, ptr + 32+8, 8);
    memcpy(name, ptr+32+8+8, 7);
    numberOfDecimalPlaces = ((char*)ptr)[32+8+7];
    memcpy(unit, ptr+32+8+8+7+1, 7);
    std::string result = std::string(sourceIdentity) + " issued " + std::to_string(numberOfShares) + " " + std::string(name)
                        + "(ManagingContractIndex: " + std::to_string(managingIndex) + ")" +
                       + ". Number of decimal: " + std::to_string(numberOfDecimalPlaces) + ". Unit of measurement: "
                       + std::to_string(unit[0]) + "-"
                       + std::to_string(unit[1]) + "-"
                       + std::to_string(unit[2]) + "-"
                       + std::to_string(unit[3]) + "-"
                       + std::to_string(unit[4]) + "-"
                       + std::to_string(unit[5]) + "-"
                       + std::to_string(unit[6]);
    return result;
}
std::string parseLogToString_qutil(uint8_t* ptr){
    std::string res = "";
    char buffer[64] = {0};
    getIdentityFromPublicKey(ptr, buffer, false);
    res = "from " + std::string(buffer) + " to ";
    getIdentityFromPublicKey(ptr+32, buffer, false);
    res += std::string(buffer) + " Amount ";
    int64_t amount;
    memcpy(&amount, ptr+64, 8);
    res += std::to_string(amount) + ": ";
    uint32_t logtype;
    memcpy(&logtype, ptr+72, 4);
    switch(logtype){
        case 0:
            res += "Success";
            break;
        case 1:
            res += "Invalid amount number";
            break;
        case 2:
            res += "insufficient fund";
            break;
        case 3:
            res += "Triggered SendToManyV1";
            break;
        case 4:
            res += "send fund via SendToManyV1";
            break;
    }
    return res;
}

std::string parseToStringBurningLog(uint8_t* ptr)
{
    char sourceIdentity[61] = { 0 };
    uint64_t burnAmount = *((uint64_t*)(ptr+32));
    uint32_t contractIndexBurnedFor = *((uint32_t*)(ptr+32+8));
    getIdentityFromPublicKey(ptr, sourceIdentity, false);
    return std::string(sourceIdentity) + " burned " + std::to_string(burnAmount) + " QU for contract index " + std::to_string(contractIndexBurnedFor);
}

struct DustBurning
{
    unsigned short numberOfBurns;

    struct Entity
    {
        unsigned char publicKey[32];
        unsigned long long amount;
    };
    static_assert(sizeof(Entity) == 40, "Unexpected size");

    unsigned int messageSize() const
    {
        return 2 + numberOfBurns * sizeof(Entity);
    }

    Entity& entity(unsigned short i)
    {
        char* buf = reinterpret_cast<char*>(this);
        return *reinterpret_cast<Entity*>(buf + i * (sizeof(Entity)) + 2);
    }
};

std::string parseToStringDustBurningLog(uint8_t* ptr, uint32_t messageSize)
{
    DustBurning* db = (DustBurning*)ptr;
    if (messageSize < 2 || messageSize > DUST_BURNING_MAX_LOG_SIZE || db->messageSize() != messageSize)
        return "null";

    std::string retVal = "balances of " + std::to_string(db->numberOfBurns) + " entities burned as dust";
    if (parseToStringDetailLevel >= 1)
    {
        char identity[61] = { 0 };
        for (int i = 0; i < db->numberOfBurns; ++i)
        {
            const DustBurning::Entity& e = db->entity(i);
            getIdentityFromPublicKey(e.publicKey, identity, false);
            retVal += "\n\t" + std::to_string(i) + ": " + std::to_string(e.amount) + " QU of " + identity;

            if (parseToStringDetailLevel < 2 && i == 1 && db->numberOfBurns > 5)
            {
                retVal += "\n\t...";
                i = db->numberOfBurns - 2;
            }
        }
    }

    return retVal;
}

std::string parseToStringSpectrumStats(uint8_t* ptr)
{
    struct SpectrumStats
    {
        unsigned long long totalAmount;
        unsigned long long dustThresholdBurnAll;
        unsigned long long dustThresholdBurnHalf;
        unsigned int numberOfEntities;
        unsigned int entityCategoryPopulations[48];
    };
    SpectrumStats* s = (SpectrumStats*)ptr;
    
    std::string retVal = std::to_string(s->totalAmount) + " QU in " + std::to_string(s->numberOfEntities)
        + " entities, dust threshold " + std::to_string(s->dustThresholdBurnAll);
    if (s->dustThresholdBurnHalf != 0)
        retVal += " (burn all <=), " + std::to_string(s->dustThresholdBurnHalf) + " (burn half <=)";
    if (parseToStringDetailLevel >= 1)
    {
        for (int i = 0; i < 48; ++i)
        {
            if (s->entityCategoryPopulations[i])
            {
                unsigned long long lowerBound = (1llu << i), upperBound = (1llu << (i + 1)) - 1;
                const char* burnIndicator = "\n\t+ bin ";
                if (lowerBound <= s->dustThresholdBurnAll)
                    burnIndicator = "\n\t- bin ";
                else if (lowerBound <= s->dustThresholdBurnHalf)
                    burnIndicator = "\n\t* bin ";
                retVal += burnIndicator + std::to_string(i) + ": " + std::to_string(s->entityCategoryPopulations[i]) + " entities with balance between "
                    + std::to_string(lowerBound) + " and " + std::to_string(upperBound);
            }
        }
    }

    return retVal;
}

std::string parseToStringContractReserveDeduction(uint8_t* ptr)
{
    uint64_t deductedAmount = *((uint64_t*)ptr);
    int64_t remainingAmount = *((int64_t*)(ptr + 8));
    uint32_t contractIndex = *((uint32_t*)(ptr + 16));

    return "contract " + std::to_string(contractIndex) + ", deducted " + std::to_string(deductedAmount) + ", remaining amount " + std::to_string(remainingAmount);
}

std::string parseLogToString_type2_type3(uint8_t* ptr){
    char sourceIdentity[61] = {0};
    char dstIdentity[61] = {0};
    char issuerIdentity[61] = {0};
    char name[8] = {0};
    char numberOfDecimalPlaces = 0;
    char unit[8] = {0};
    long long numberOfShares = 0;
    long long managingIndex = 0;
    const bool isLowerCase = false;
    getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr + 32, dstIdentity, isLowerCase);
    getIdentityFromPublicKey(ptr + 64, issuerIdentity, isLowerCase);
    memcpy(&numberOfShares, ptr + 96, 8);
    memcpy(&managingIndex, ptr + 96 + 8, 8);
    memcpy(name, ptr + 96 + 8 + 8, 7);
    numberOfDecimalPlaces = ((char*)ptr)[96 + 8 + 8 + 7];
    memcpy(unit, ptr + 96 + 8 + 8 + 7 + 1, 7);
    std::string result = "from " + std::string(sourceIdentity) + " to " + std::string(dstIdentity) + " " + std::to_string(numberOfShares) + " " + std::string(name)
                         + "(Issuer: " + std::string(issuerIdentity) + ")"
                         + "(ManagingContractIndex: " + std::to_string(managingIndex) + ")" +
                         + ". Number of decimal: " + std::to_string(numberOfDecimalPlaces) + ". Unit of measurement: "
                         + std::to_string(unit[0]) + "-"
                         + std::to_string(unit[1]) + "-"
                         + std::to_string(unit[2]) + "-"
                         + std::to_string(unit[3]) + "-"
                         + std::to_string(unit[4]) + "-"
                         + std::to_string(unit[5]) + "-"
                         + std::to_string(unit[6]);
    return result;
}

std::string getOracleQueryStatusString(uint8_t status)
{
    constexpr uint8_t ORACLE_QUERY_STATUS_PENDING = 1;     ///< Query is being processed.
    constexpr uint8_t ORACLE_QUERY_STATUS_COMMITTED = 2;   ///< The quorum has committed to a oracle reply, but it has not been revealed yet.
    constexpr uint8_t ORACLE_QUERY_STATUS_SUCCESS = 3;     ///< The oracle reply has been confirmed and is available.
    constexpr uint8_t ORACLE_QUERY_STATUS_UNRESOLVABLE = 5;///< No valid oracle reply is available, because computors disagreed about the value.
    constexpr uint8_t ORACLE_QUERY_STATUS_TIMEOUT = 4;     ///< No valid oracle reply is available and timeout has hit.

    switch (status)
    {
    case ORACLE_QUERY_STATUS_PENDING:
        return "pending";
    case ORACLE_QUERY_STATUS_COMMITTED:
        return "committed";
    case ORACLE_QUERY_STATUS_SUCCESS:
        return "success";
    case ORACLE_QUERY_STATUS_UNRESOLVABLE:
        return "unresolvable";
    case ORACLE_QUERY_STATUS_TIMEOUT:
        return "timeout";
    default:
        return "unknown";
    }
}

std::string parseToStringOracleQueryStatusChange(uint8_t* ptr)
{
    constexpr uint8_t ORACLE_QUERY_TYPE_CONTRACT_QUERY = 0;
    constexpr uint8_t ORACLE_QUERY_TYPE_CONTRACT_SUBSCRIPTION = 1;
    constexpr uint8_t ORACLE_QUERY_TYPE_USER_QUERY = 2;

    uint64_t queryingEntity0 = *((uint64_t*)ptr);
    int64_t queryId = *(int64_t*)(ptr + 32);
    uint32_t interfaceIndex = *(uint32_t*)(ptr + 40);
    uint8_t type = *(uint8_t*)(ptr + 44);
    uint8_t status = *(uint8_t*)(ptr + 45);

    std::string s = "status " + getOracleQueryStatusString(status) + ", queryId " + std::to_string(queryId) + ", interface " + std::to_string(interfaceIndex) + ", origin ";

    if (type == ORACLE_QUERY_TYPE_CONTRACT_QUERY)
    {
        s += "contract " + std::to_string(queryingEntity0);
    }
    else if (type == ORACLE_QUERY_TYPE_CONTRACT_SUBSCRIPTION)
    {
        s += "subscriptionId " + std::to_string(queryingEntity0);
    }
    else if (type == ORACLE_QUERY_TYPE_USER_QUERY)
    {
        char sourceIdentity[61] = { 0 };
        const bool isLowerCase = false;
        getIdentityFromPublicKey(ptr, sourceIdentity, isLowerCase);
        s += "user " + std::string(sourceIdentity);
    }

    return s;
}

std::string dateAndTimeToString(uint64_t dateAndTime)
{
    uint64_t year = dateAndTime >> 46;
    uint64_t month = (dateAndTime >> 42) & 0b1111;
    uint64_t day = (dateAndTime >> 37) & 0b11111;
    uint64_t hour = (dateAndTime >> 32) & 0b11111;
    uint64_t minute = (dateAndTime >> 26) & 0b111111;
    uint64_t second = (dateAndTime >> 20) & 0b111111;
    uint64_t millisecond = (dateAndTime >> 10) & 0b1111111111;
    uint64_t microsecondDuringMillisecond = dateAndTime & 0b1111111111;
    std::stringstream ss;
    ss << std::setfill('0') << year << "-"
        << std::setw(2) << month << "-"
        << std::setw(2) << day << " "
        << std::setw(2) << hour << ":"
        << std::setw(2) << minute << ":"
        << std::setw(2) << second << "."
        << std::setw(3) << millisecond << "'"
        << std::setw(3) << microsecondDuringMillisecond;
    return ss.str();
}

std::string parseToStringOracleSubscriberMessage(uint8_t* ptr)
{
    constexpr uint8_t ORACLE_QUERY_TYPE_CONTRACT_QUERY = 0;
    constexpr uint8_t ORACLE_QUERY_TYPE_CONTRACT_SUBSCRIPTION = 1;
    constexpr uint8_t ORACLE_QUERY_TYPE_USER_QUERY = 2;

    int32_t subscriptionId = *((int32_t*)ptr);
    uint32_t interfaceIndex = *(uint32_t*)(ptr + 4);
    uint32_t contractIndex = *(uint32_t*)(ptr + 8);
    uint32_t periodInMilliseconds = *(uint32_t*)(ptr + 12);
    uint64_t firstQueryDateAndTime = *(int64_t*)(ptr + 16);

    std::string s = "contract " + std::to_string(contractIndex);
    if (periodInMilliseconds == 0)
        s += " un";
    s += "subscribed subscriptionId " + std::to_string(subscriptionId) + ", interface " + std::to_string(interfaceIndex)
        + ", period " + std::to_string(periodInMilliseconds / 60000) + " minutes";
    if (firstQueryDateAndTime)
    {
        s += ", first query at " + dateAndTimeToString(firstQueryDateAndTime);
    }
    return s;
}

unsigned long long printQubicLog(uint8_t* logBuffer, int bufferSize, uint64_t fromId, uint64_t toId){
    if (bufferSize == 0){
        LOG("Empty log\n");
        return -1;
    }
    if (bufferSize < LOG_HEADER_SIZE){
        LOG("Buffer size is too small (not enough to contain the header), expected 26 | received %d\n", bufferSize);
        return -1;
    }
    uint8_t* end = logBuffer + bufferSize;
    unsigned long long retLogId = 0;
    bool isBigChunk = false;
    if (toId - fromId > 3000)
    {
        isBigChunk = true;
        printf("[LARGE LOGGING BATCH => ONLY PRINT HEAD AND TAIL]\n");
    }
    while (logBuffer < end){
        // basic info
        uint16_t epoch = *((unsigned short*)(logBuffer));
        uint32_t tick = *((unsigned int*)(logBuffer + 2));
        uint32_t tmp = *((unsigned int*)(logBuffer + 6));
        uint64_t logId = *((unsigned long long*)(logBuffer + 10));
        if (logId > retLogId) retLogId = logId;
        uint64_t logDigest = *((unsigned long long*)(logBuffer + 18));
        uint8_t messageType = tmp >> 24;
        std::string mt = logTypeToString(messageType);
        uint32_t messageSize = (tmp << 8) >> 8;
        if (logBuffer + LOG_HEADER_SIZE + messageSize > end)
        {
            LOG("Error: log buffer contains incomplete log message (log ID %llu)", logId);
            return retLogId;
        }
        {
            uint64_t computedLogDigest = 0;
            KangarooTwelve(logBuffer + LOG_HEADER_SIZE, messageSize, (uint8_t*) & computedLogDigest, 8);
            if (logDigest != computedLogDigest)
            {
                LOG("------------------------------\n");
                LOG("WARNING: mismatched log digest\n");
                LOG("------------------------------\n");
                return retLogId;
            }
        }
        logBuffer += LOG_HEADER_SIZE;
        std::string humanLog = "null";
        switch(messageType){
            case QU_TRANSFER:
                if (messageSize == QU_TRANSFER_LOG_SIZE){ // with or without transfer ID
                    humanLog = parseLogToString_type0(logBuffer);
                } else {
                    LOG("Malfunction buffer size for QU_TRANSFER log\n");
                }
                break;
            case ASSET_ISSUANCE:
                if (messageSize == ASSET_ISSUANCE_LOG_SIZE){
                    humanLog = parseLogToString_type1(logBuffer);
                } else {
                    LOG("Malfunction buffer size for ASSET_ISSUANCE log\n");
                }
                break;
            case ASSET_OWNERSHIP_CHANGE:
                if (messageSize == ASSET_OWNERSHIP_CHANGE_LOG_SIZE){
                    humanLog = parseLogToString_type2_type3(logBuffer);
                } else {
                    LOG("Malfunction buffer size for ASSET_OWNERSHIP_CHANGE log\n");
                }
                break;
            case ASSET_POSSESSION_CHANGE:
                if (messageSize == ASSET_POSSESSION_CHANGE_LOG_SIZE){
                    humanLog = parseLogToString_type2_type3(logBuffer);
                } else {
                    LOG("Malfunction buffer size for ASSET_POSSESSION_CHANGE log\n");
                }
                break;
            case BURNING:
                if (messageSize == BURNING_LOG_SIZE) {
                    humanLog = parseToStringBurningLog(logBuffer);
                }
                else {
                    LOG("Malfunction buffer size for BURNING log\n");
                }
                break;
            case DUST_BURNING:
                humanLog = parseToStringDustBurningLog(logBuffer, messageSize);
                if (humanLog == "null") {
                    LOG("Malfunction buffer size for DUST_BURNING log\n");
                }
                break;
            case SPECTRUM_STATS:
                if (messageSize == SPECTRUM_STATS_LOG_SIZE) {
                    humanLog = parseToStringSpectrumStats(logBuffer);
                }
                else {
                    LOG("Malfunction buffer size for SPECTRUM_STATS log\n");
                }
                break;
            case CONTRACT_RESERVE_DEDUCTION:
                if (messageSize == CONTRACT_RESERVE_DEDUCTION_LOG_SIZE) {
                    humanLog = parseToStringContractReserveDeduction(logBuffer);
                }
                else {
                    LOG("Malfunction buffer size for CONTRACT_RESERVE_DEDUCTION log\n");
                }
                break;
            case ORACLE_QUERY_STATUS_CHANGE:
                if (messageSize == ORACLE_QUERY_STATUS_CHANGE_LOG_SIZE) {
                    humanLog = parseToStringOracleQueryStatusChange(logBuffer);
                }
                else {
                    LOG("Unexpected log message size for ORACLE_QUERY_STATUS_CHANGE\n");
                }
                break;
            case ORACLE_SUBSCRIBER_MESSAGE:
                if (messageSize == ORACLE_SUBSCRIBER_MESSAGE_LOG_SIZE) {
                    humanLog = parseToStringOracleSubscriberMessage(logBuffer);
                }
                else {
                    LOG("Unexpected log message size for ORACLE_SUBSCRIBER_MESSAGE\n");
                }
                break;
            // TODO: stay up-to-date with core node contract logger
            case CONTRACT_INFORMATION_MESSAGE:
            case CONTRACT_ERROR_MESSAGE:
            case CONTRACT_WARNING_MESSAGE:
            case CONTRACT_DEBUG_MESSAGE:
            case 255:
            {
                unsigned int contractId = ((uint32_t*)logBuffer)[0];
                humanLog = "Contract ID #" + std::to_string(contractId) + " ";
                if (messageType == CONTRACT_INFORMATION_MESSAGE) humanLog += "INFO: ";
                if (messageType == CONTRACT_ERROR_MESSAGE) humanLog += "ERROR: ";
                if (messageType == CONTRACT_WARNING_MESSAGE) humanLog += "WARNING: ";
                if (messageType == CONTRACT_DEBUG_MESSAGE) humanLog += "DEBUG: ";
                if (messageType == 255) humanLog += "CUSTOM: ";
                char buff[1024 * 2] = { 0 };
                byteToHex(logBuffer + 4, buff, messageSize - 4);
                humanLog += std::string(buff);
                break;
            }
        }
        if (isBigChunk)
        {
            if ((logId < (fromId + 10) || (logId > toId - 10)))
            {
                LOG("[%llu] %u.%03d %s: %s\n", logId, tick, epoch, mt.c_str(), humanLog.c_str());
            }
        }
        else
        {
            LOG("[%llu] %u.%03d %s: %s\n", logId, tick, epoch, mt.c_str(), humanLog.c_str());
        }
        
        
        if (humanLog == "null"){
            char buff[1024*2 + 1] = {0};
            for (unsigned int i = 0; i < std::min(messageSize, (uint32_t)1024); i++){
                sprintf(buff + i*2, "%02x", logBuffer[i]);
            }
            LOG("NO parser for this message yet | Original message (%u bytes): %s%s\n", messageSize, buff, (messageSize > 1024) ? "..." : "");
        }
        logBuffer+= messageSize;
    }
    return retLogId;
}
