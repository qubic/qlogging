#include "structs.h"
#include <stdexcept>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#include <Winsock2.h>
#include <Ws2tcpip.h>
#define close(x) closesocket(x)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <cstring>

#include "connection.h"
#include "logger.h"
#ifndef min
#define min(x,y) std::min(x,y)
#endif
#ifdef _MSC_VER
static int connect(const char* nodeIp, int nodePort)
{
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 0), &wsa_data);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    size_t tv = 1000;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(nodePort);

    if (inet_pton(AF_INET, nodeIp, &addr.sin_addr) <= 0) {
        LOG("Error translating command line ip address to usable one.");
        return -1;
    }
    int res = connect(serverSocket, (const sockaddr*)&addr, sizeof(addr));
    if (res < 0) {
        LOG("Failed to connect %s | error %d\n", nodeIp, res);
        return -1;
    }
    return serverSocket;
}
#else
static int connect(const char* nodeIp, int nodePort)
{
	int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
    sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(nodePort);

    if (inet_pton(AF_INET, nodeIp, &addr.sin_addr) <= 0) {
        LOG("Error translating command line ip address to usable one.");
        return -1;
    }

    if (connect(serverSocket, (const sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("Failed to connect %s\n", nodeIp);
        return -1;
    }
    return serverSocket;
}
#endif
QubicConnection::QubicConnection(const char* nodeIp, int nodePort)
{
	memset(mNodeIp, 0, 32);
	memcpy(mNodeIp, nodeIp, strlen(nodeIp));
	mNodePort = nodePort;
	mSocket = connect(nodeIp, nodePort);
    if (mSocket < 0)
        throw std::logic_error("No connection.");
}
QubicConnection::~QubicConnection()
{
	close(mSocket);
}

int QubicConnection::receiveData(uint8_t* buffer, int sz)
{
    int count = 0;
    while (sz)
    {
        auto ret = recv(mSocket, (char*)buffer + count, min(1024,sz), 0);
        if (ret == -1)
        {
            return -1;
        }
        count += ret;
        sz -= ret;
    }
	return count;
}
void QubicConnection::receiveAFullPacket(std::vector<uint8_t>& buffer)
{
    // first receive the header
    RequestResponseHeader header;
    int recvByte = receiveData((uint8_t*)&header, sizeof(RequestResponseHeader));
    if (recvByte != sizeof(RequestResponseHeader)) throw std::logic_error("No connection.");
    int packet_size = header.size();
    buffer.resize(header.size());
    memcpy(buffer.data(), &header, sizeof(RequestResponseHeader));
    // receive the rest
    recvByte = receiveData(buffer.data() + sizeof(RequestResponseHeader), packet_size - sizeof(RequestResponseHeader));
    if (recvByte != packet_size - sizeof(RequestResponseHeader)) throw std::logic_error("No connection.");
}

template <typename T>
T QubicConnection::receivePacketAs()
{
    // first receive the header
    RequestResponseHeader header;
    int recvByte = receiveData((uint8_t*)&header, sizeof(RequestResponseHeader));
    if (recvByte != sizeof(RequestResponseHeader))
    {
        throw std::logic_error("No connection.");
    }
    int packet_size = header.size();
    T result;
    memset(&result, 0, sizeof(T));
    if (packet_size - sizeof(RequestResponseHeader))
    {
        memset(mBuffer, 0, packet_size - sizeof(RequestResponseHeader));
        // receive the rest
        recvByte = receiveData(mBuffer, packet_size - sizeof(RequestResponseHeader));
        if (recvByte != packet_size - sizeof(RequestResponseHeader)){
            throw std::logic_error("No connection.");
        }
        result = *((T*)mBuffer);
    }
    return result;
}

int QubicConnection::sendData(uint8_t* buffer, int sz)
{
    int size = sz;
    int numberOfBytes;
    while (size) {
        if ((numberOfBytes = send(mSocket, (char*)buffer, size, 0)) <= 0) {
            return 0;
        }
        buffer += numberOfBytes;
        size -= numberOfBytes;
    }
	return sz - size;
}

template ResponseLogIdRange QubicConnection::receivePacketAs<ResponseLogIdRange>();
template TickData QubicConnection::receivePacketAs<TickData>();