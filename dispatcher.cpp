#include "dispatcher.h"

void Dispatcher::wakeThread(WorkerThread* pWThread)
{
    pWThread->sleeping_state_mtx.lock();
    while(!pWThread->sleeping)//to prevent falling asleep while next one is STILL awake
    {
        pWThread->sleeping_state_mtx.unlock();
        std::this_thread::sleep_for(std::chrono::nanoseconds(1000));
        pWThread->sleeping_state_mtx.lock();
    }

    while(pWThread->sleeping)
    {
        pWThread->sleeping_state_mtx.unlock();

        std::lock_guard<std::mutex> lk(pWThread->wakeUp_mtx);
        pWThread->wakeUp_cv.notify_all();
        std::this_thread::sleep_for(std::chrono::nanoseconds(1000));

        pWThread->sleeping_state_mtx.lock();
    }
    pWThread->sleeping_state_mtx.unlock();
}

bool Dispatcher::initThread(WorkerThread* pThread, WorkerThread* pPrevThread, WorkerThread* pNextThread, std::mutex* pSocketMutex, QUdpSocket* pReadSocket,
                            const char* if_name)
{
    if(!pThread->init_socket(if_name))
        return false;
    pThread->timer.start();

    pThread->waitingToSend = true;

    pThread->set_pointers(pReadSocket, pSocketMutex, this, &pNextThread->allowSend,
                          &pNextThread->allowSend_mtx, &pNextThread->waitingToSend,
                          &pNextThread->waitingToSend_mtx, pPrevThread, pNextThread);

    return true;
}

Dispatcher::Dispatcher(const char* if_name)
{
    WorkerThread wThread1;
    WorkerThread wThread2;
    WorkerThread wThread3;

    WorkerThread* threadsPool [THREADS_POOL_SIZE] =
    {
        &wThread1,
        &wThread2,
        &wThread3
    };

    std::mutex socketMutex;
    QUdpSocket readSocket;

    bool initSuccess;

    if(!readSocket.bind(QHostAddress(TELEMETRY_CHAIN_IP), I_PORT))
        initSuccess = false;

    for(quint8 i = 0; i < THREADS_POOL_SIZE; i++)
    {
        if(!i)
        {
            initSuccess = initThread(threadsPool[i], threadsPool[THREADS_POOL_SIZE-1], threadsPool[i+1],
                                     &socketMutex, &readSocket, if_name);
        }
        else if(i == THREADS_POOL_SIZE-1)
        {
            initSuccess = initThread(threadsPool[i], threadsPool[i-1], threadsPool[0],
                                     &socketMutex, &readSocket, if_name);
        }
        else
        {
            initSuccess = initThread(threadsPool[i], threadsPool[i-1] , threadsPool[i+1],
                                     &socketMutex, &readSocket, if_name);
        }

        if(!initSuccess)
            break;
    }

    threadsPool[0]->waitingToSend = false;

    if(initSuccess)
    {
        for (int i = 0; i < THREADS_POOL_SIZE; ++i)
        {
            threadsPool[i]->start();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        quint16 iThread = 0;
        while(true)
        {
            std::this_thread::sleep_for(std::chrono::nanoseconds(INTERVAL_BTWN_OUTP));
            wakeThread(threadsPool[iThread]);

            iThread++;
            if(iThread > THREADS_POOL_SIZE-1)
                iThread = 0;
        }
    }
    else
    {
        fprintf(stderr, "Failed to initiate libpcap or udp socket");
        exit(1);
    }
}
