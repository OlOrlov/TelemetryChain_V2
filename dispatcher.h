#ifndef COMMUNICATIONSMANAGER_H
#define COMMUNICATIONSMANAGER_H
#include <QObject>
#include <QThread>
#include <thread>
#include <chrono>
#include <QElapsedTimer>
#include <QUdpSocket>
#include <condition_variable>

#include <pcap.h>

#if defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#define SHTDWN_TYPE SHUT_RDWR

#elif defined(Q_OS_WIN)
#define SHTDWN_TYPE SD_BOTH
#undef _WIN64
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib,"ws2_32.lib") //For winsock
#pragma comment(lib,"wpcap.lib") //For winpcap
struct ether_header
{
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};
#define ETH_P_LOOPBACK  0x9000
#endif

#include "workerthread.h"

/**********************/
/*CONNECTION SETTINGS*/
#define I_PORT             1024
#define TELEMETRY_CHAIN_IP "127.0.1.1"
#define SOURCE_IP          "127.0.2.1"
#define SOURCE_MAC         "255.255.255.255.255.255"
#define DEST_MAC           "255.255.255.255.255.255"
#define SEND_EMPTY         true
/**********************/

#define TRY_WAIT_FOR_PREV_SEND 307200
#define INTERVAL_BTWN_OUTP       51200//ns. Output: 64 bytes (eth frame), with 10 mbps -> 51200 nsec time frame
#define EMPTY_MSG                Q_NULLPTR
#define INPUT_SIZE               37
#define RAW_OUTPUT_SIZE          8
#define OUTPUT_SIZE              12
#define HAMMING_BITS             15
#define HAMMING_DATA_BITS        11
#define ETH_PACK_MINLEN          42
#define ETH_PAD_LEN              4
#define THREADS_POOL_SIZE        3

class WorkerThread;

class Dispatcher : public QObject
{
    Q_OBJECT
public:
    Dispatcher(const char* if_name);

    quint8 fragment[4];
    bool haveFragment = false;
    std::mutex fragmentMutex;
private:
    bool initThread(WorkerThread* pThread, WorkerThread* pPrevThread, WorkerThread* pNextThread,
                    std::mutex* pSocketMutex, QUdpSocket* pReadSocket, const char* if_name);
    void wakeThread(WorkerThread* pWThread);
};

#endif // COMMUNICATIONSMANAGER_H
