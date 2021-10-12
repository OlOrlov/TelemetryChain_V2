#include "dispatcher.h"
#include "workerthread.h"

WorkerThread::WorkerThread()
{
    ip_source.setAddress(SOURCE_IP);
}

void WorkerThread::set_pointers(QUdpSocket* inp_pSock, std::mutex* inp_pSock_mtx, Dispatcher* inp_pDispatcher,
                                std::condition_variable* inp_pLetNextSend, std::mutex* inp_pLetNextSend_mtx,
                                bool* inp_pNextWaitingToSend, std::mutex* inp_waitingToSend_mtx,
                                WorkerThread* inp_pPrevWorker, WorkerThread* inp_pNextWorker)
{
    pRcvSocket = inp_pSock;
    pDispatcher = inp_pDispatcher;

    pLetNextSend = inp_pLetNextSend;
    pLetNextSend_mtx = inp_pLetNextSend_mtx;

    pSock_mtx = inp_pSock_mtx;

    pNextWaitingToSend = inp_pNextWaitingToSend;
    pNextWaitingToSend_mtx = inp_waitingToSend_mtx;

    pPrevWorker = inp_pPrevWorker;
    pNextWorker = inp_pNextWorker;
}

bool WorkerThread::init_socket(const char* inp_if_name)
{
    if_name = inp_if_name;

    QString str(DEST_MAC);
    QString fragm;
    quint8 j = 0;
    for(int i = 0; i < str.length(); i++)
        if(str[i] != '.')
        {
            fragm.append(str[i]);
        }
        else
        {
            header.ether_dhost[j] = fragm.toInt();
            fragm.clear();
            j++;
        }
    header.ether_dhost[j] = fragm.toInt();

    str = SOURCE_MAC;
    fragm.clear();
    j = 0;
    for(int i = 0; i < str.length(); i++)
        if(str[i] != '.')
        {
            fragm.append(str[i]);
        }
        else
        {
            header.ether_shost[j] = fragm.toInt();
            fragm.clear();
            j++;
        }
    header.ether_shost[j] = fragm.toInt();

    header.ether_type = htons(ETH_P_LOOPBACK);

    #if defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
        struct ifreq ifr;
        size_t if_name_len = strlen(if_name);
        if (if_name_len<sizeof(ifr.ifr_name))
        {
            memcpy(ifr.ifr_name, if_name, if_name_len);
            ifr.ifr_name[if_name_len]=0;
        }
        else
        {
            fprintf(stderr,"interface name is too long");
            return false;
        }
    #endif

    // Open an IPv4-family socket for use when calling ioctl.
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        perror(0);
        return false;
    }

    #if defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
        // Obtain the source MAC address, copy into Ethernet header
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
        {
            perror(0);
            shutdown(fd, SHTDWN_TYPE);
            return false;
        }
        if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        {
            fprintf(stderr,"not an Ethernet interface");
            shutdown(fd, SHTDWN_TYPE);
            return false;
        }
        const unsigned char* source_mac_addr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        memcpy(header.ether_shost, source_mac_addr, sizeof(header.ether_shost));
    #endif

    shutdown(fd, SHTDWN_TYPE);

    return true;
}

void WorkerThread::run()
{
    while(true)
    {
        sleeping_state_mtx.lock();
        sleeping = false;//Report to prev worker
        sleeping_state_mtx.unlock();

        pSock_mtx->lock();
        if(pRcvSocket->hasPendingDatagrams())
        {
            quint64 datagramSize = pRcvSocket->pendingDatagramSize();
            if(datagramSize == INPUT_SIZE)
            {
                quint8 received[INPUT_SIZE];
                pRcvSocket->readDatagram(reinterpret_cast<char*>(received), datagramSize, &ip_source, &i_port);
                pSock_mtx->unlock();

                if(filterIntput(received[0]))
                {
                    quint8 inoutRec1[OUTPUT_SIZE];
                    quint8 inoutRec2[OUTPUT_SIZE];
                    quint8 inoutRec3[OUTPUT_SIZE];
                    quint8 inoutRec4[OUTPUT_SIZE];
                    quint8 inoutRec5[OUTPUT_SIZE];
                    processDG(reinterpret_cast<quint8*>(&received),
                              reinterpret_cast<quint8*>(&inoutRec1),
                              reinterpret_cast<quint8*>(&inoutRec2),
                              reinterpret_cast<quint8*>(&inoutRec3),
                              reinterpret_cast<quint8*>(&inoutRec4),
                              reinterpret_cast<quint8*>(&inoutRec5));

                    waitPrevSend();
                    this->setPriority(QThread::TimeCriticalPriority);//<<< Time critical zone
                    timer.restart();
                    if(timer.nsecsElapsed() < INTERVAL_BTWN_OUTP)
                        std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP));
                    timer.restart();

                    prepareOutput(reinterpret_cast<quint8*>(&inoutRec1));
                    send(reinterpret_cast<quint8*>(&inoutRec1));
                    std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP - timer.nsecsElapsed()));

                    timer.restart();
                    prepareOutput(reinterpret_cast<quint8*>(&inoutRec2));
                    send(reinterpret_cast<quint8*>(&inoutRec2));
                    std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP - timer.nsecsElapsed()));

                    timer.restart();
                    prepareOutput(reinterpret_cast<quint8*>(&inoutRec3));
                    send(reinterpret_cast<quint8*>(&inoutRec3));
                    std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP - timer.nsecsElapsed()));

                    timer.restart();
                    prepareOutput(reinterpret_cast<quint8*>(&inoutRec4));
                    send(reinterpret_cast<quint8*>(&inoutRec4));

                    if(haveFullFifthRec)
                    {
                        std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP - timer.nsecsElapsed()));
                        prepareOutput(reinterpret_cast<quint8*>(&inoutRec5));
                        send(reinterpret_cast<quint8*>(&inoutRec5));
                        haveFullFifthRec = false;
                    }

                    this->setPriority(QThread::HighestPriority);//>>> Time critical zone
                    letNextWorkerSend();

                }
                else
                {
                    sendEmpty();
                }
            }
            else
            {
                quint8 trash[1];
                pRcvSocket->readDatagram(reinterpret_cast<char*>(trash), datagramSize, &ip_source, &i_port);
                pSock_mtx->unlock();
                sendEmpty();
            }
        }
        else
        {
            pSock_mtx->unlock();
            sendEmpty();
        }
        sleeping_state_mtx.lock();
        sleeping = true;
        sleeping_state_mtx.unlock();
        std::unique_lock<std::mutex> lk(wakeUp_mtx);
        wakeUp_cv.wait(lk);
    }
}

void WorkerThread::waitPrevSend()
{
    waitingToSend_mtx.lock();

    if(waitingToSend)
    {
        waitingToSend_mtx.unlock();

        std::unique_lock<std::mutex> lk(allowSend_mtx);
        allowSend.wait_until(lk, std::chrono::system_clock::now() + std::chrono::nanoseconds(TRY_WAIT_FOR_PREV_SEND));

        waitingToSend_mtx.lock();

        waitingToSend = true;//Should expect that will need to wait
        waitingToSend_mtx.unlock();

    }
    else
        waitingToSend_mtx.unlock();
}

void WorkerThread::sendEmpty()
{
    if(SEND_EMPTY)
    {
        waitPrevSend();
        this->setPriority(QThread::TimeCriticalPriority);//<<< Time critical zone
        std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP));
        send(EMPTY_MSG);
        letNextWorkerSend();//At this moment next worker read new DG and waits
        this->setPriority(QThread::HighestPriority);//>>> Time critical zone
    }
}

void WorkerThread::processDG(quint8* received, quint8* rec1, quint8* rec2,
                             quint8* rec3, quint8* rec4, quint8* rec5)
{
    quint8 elemShift = 0;
    pDispatcher->fragmentMutex.lock();
    if(pDispatcher->haveFragment)
    {
        rec1[0] = pDispatcher->fragment[0];
        rec1[1] = pDispatcher->fragment[1];
        rec1[2] = pDispatcher->fragment[2];
        rec1[3] = pDispatcher->fragment[3];
        pDispatcher->haveFragment = false;
        pDispatcher->fragmentMutex.unlock();
        haveFullFifthRec = true;
        elemShift = 4;
    }
    else
    {
        pDispatcher->fragment[0] = received[33];
        pDispatcher->fragment[1] = received[34];
        pDispatcher->fragment[2] = received[35];
        pDispatcher->fragment[3] = received[36];
        pDispatcher->haveFragment = true;
        pDispatcher->fragmentMutex.unlock();
    }

    quint16 i = 1;
    while(i < 33)
    {
        for(quint16 j = elemShift; j < 8; j++)
        {
            rec1[j] = received[i];
            i += 1;
        }
        for(quint16 j = 0; j < 8; j++)
        {
            rec2[j] = received[i];
            i += 1;
        }
        for(quint16 j = 0; j < 8; j++)
        {
            rec3[j] = received[i];
            i += 1;
        }
        for(quint16 j = 0; j < 8; j++)
        {
            rec4[j] = received[i];
            i += 1;
        }

        if(elemShift)
            for(quint16 j = 0; j < 4 + elemShift; j++)
            {
                rec5[j] = received[i];
                i += 1;
            }
    }
}

bool WorkerThread::filterIntput(quint8 rec)
{
    if((rec&2) != 2)
        return false;
    else
        return true;
}

quint16 WorkerThread::makeHammingCode(quint32 inp, quint16 numBits)//(15,11)
{
    bool bit[HAMMING_DATA_BITS];
    for(int i = 0; i != HAMMING_DATA_BITS; i++)
        bit[i] = (inp >> (numBits - i - 1)) & 1;

    bool parity1 = bit[0]^bit[1]^bit[3]^bit[4]^bit[6]^bit[8]^bit[10];
    bool parity2 = bit[0]^bit[2]^bit[3]^bit[5]^bit[6]^bit[9]^bit[10];
    bool parity4 = bit[1]^bit[2]^bit[3]^bit[7]^bit[8]^bit[9]^bit[10];
    bool parity8 = bit[4]^bit[5]^bit[6]^bit[7]^bit[8]^bit[9]^bit[10];

    return (parity1 << 14) +
           (parity2 << 13) +
           (bit[0] << 12) +
           (parity4 << 11) +
           (bit[1] << 10) +
           (bit[2] << 9) +
           (bit[3] << 8) +
           (parity8 << 7) +
           (bit[4] << 6) +
           (bit[5] << 5) +
           (bit[6] << 4) +
           (bit[7] << 3) +
           (bit[8] << 2) +
           (bit[9] << 1) +
           bit[10];
}

void WorkerThread::prepareOutput(quint8* inpArr)
{
    quint64 bankCoded = 0;
    quint8 bankCodedNBits = 0;
    quint32 bankUncoded = 0;
    quint8 bankUncodedNBits = 0;

    quint8 outArr[OUTPUT_SIZE];
    quint16 mask;
    quint16 outpNum = 0;

    for(int i = 0; i < 8; i++)
    {
        bankUncoded = (bankUncoded << 8) + inpArr[i];
        bankUncodedNBits += 8;
        if(bankUncodedNBits > HAMMING_DATA_BITS)
        {
            bankCoded = (bankCoded << HAMMING_BITS) + makeHammingCode(bankUncoded, bankUncodedNBits);
            bankCodedNBits += HAMMING_BITS;

            mask = 0xFFFF;
            mask <<= bankUncodedNBits - HAMMING_DATA_BITS;
            mask = ~mask;
            bankUncoded &= mask;

            bankUncodedNBits -= HAMMING_DATA_BITS;

            while(bankCodedNBits > 8)
            {
                outArr[outpNum] = bankCoded >> (bankCodedNBits - 8);
                mask = 0xFFFF;
                mask <<= bankCodedNBits - 8;
                mask = ~mask;
                bankCoded &= mask;
                bankCodedNBits -= 8;
                outpNum += 1;
            }
        }

        if(i == 7)
        {
            bankCoded = (bankCoded << HAMMING_BITS) + makeHammingCode(bankUncoded, bankUncodedNBits);
            bankCodedNBits += HAMMING_BITS;

            while(true)
            {
                if(bankCodedNBits > 8)
                {
                    outArr[outpNum] = bankCoded >> (bankCodedNBits - 8);
                    mask = 0xFFFF;
                    mask <<= bankCodedNBits - 8;
                    mask = ~mask;
                    bankCoded &= mask;
                    bankCodedNBits -= 8;
                    outpNum += 1;
                }
                else
                {
                    outArr[outpNum] = bankCoded << (8 - bankCodedNBits);
                    break;
                }
            }
        }
    }

    for(int i = 0; i < OUTPUT_SIZE; i++)
        inpArr[i] = outArr[i];
}

void WorkerThread::send(quint8* toSend)
{
    quint8 subst[ETH_PACK_MINLEN + ETH_PAD_LEN] = {0,};

    if(toSend != EMPTY_MSG)
        for(int i = 0; i < 12; i++)
            subst[i + ETH_PAD_LEN] = toSend[i];

    // Combine the Ethernet header and msg into a contiguous block.
    unsigned char frame[sizeof(struct ether_header) + sizeof(subst)];
    memcpy(frame, &header, sizeof(struct ether_header));
    memcpy(frame + sizeof(struct ether_header), &subst, sizeof(subst));

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';
    pcap_t* pcap = pcap_open_live(if_name, 96, 0, 0, pcap_errbuf);

    if (pcap_errbuf[0]!='\0')
    {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }

    if (!pcap)
    {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,frame, 60) == -1)
    {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);
}

void WorkerThread::letNextWorkerSend()
{
    pNextWaitingToSend_mtx->lock();
    if(*pNextWaitingToSend)
        *pNextWaitingToSend = false;//In case if it didn't finished preparing DG yet
    pNextWaitingToSend_mtx->unlock();

    std::lock_guard<std::mutex> lk(*pLetNextSend_mtx);
    pLetNextSend->notify_all();
}
