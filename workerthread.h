#ifndef WORKERTHREAD_H
#define WORKERTHREAD_H
#include "dispatcher.h"

class Dispatcher;

class WorkerThread : public QThread
{
    Q_OBJECT
public:
    WorkerThread();
    void set_pointers(QUdpSocket* inp_pSock, std::mutex* inp_pSock_mtx, Dispatcher* inp_pDispatcher,
                      std::condition_variable* inp_pLetNextSend, std::mutex* inp_pLetNextSend_mtx,
                      bool* inp_pNextWaitingToSend, std::mutex* inp_waitingToSend_mtx,
                      WorkerThread* inp_pPrevWorker, WorkerThread* inp_pNextWorker);

    bool init_socket(const char* inp_if_name);

    std::mutex waitingToSend_mtx;
    bool waitingToSend;

    std::condition_variable allowSend;
    std::mutex allowSend_mtx;

    std::condition_variable* pLetNextSend;
    std::mutex* pLetNextSend_mtx;

    std::mutex sleeping_state_mtx;
    bool sleeping = true;
    std::mutex wakeUp_mtx;
    std::condition_variable wakeUp_cv;

    QElapsedTimer timer;

protected:
    void run() override;

private:
    ether_header header;
    const char* if_name;

    WorkerThread* pPrevWorker;// need to protect?
    WorkerThread* pNextWorker;

    std::mutex* pSock_mtx;
    bool* pNextWaitingToSend;
    std::mutex* pNextWaitingToSend_mtx;

    void waitPrevSend();
    void letNextWorkerSend();//MUST happen only after the last sending
    quint16 i_port;
    QHostAddress ip_source;
    QUdpSocket* pRcvSocket;
    Dispatcher* pDispatcher;
    void sendEmpty();
    void processDG(quint8* received, quint8* rec1,
                   quint8* rec2, quint8* rec3,
                   quint8* rec4, quint8* rec5);
    bool filterIntput(quint8 rec);
    quint16 makeHammingCode(quint32 inp, quint16 numBits);
    void prepareOutput(quint8* inpArr);
    void send(quint8* toSend);
    bool haveFullFifthRec = false;
};

#endif // WORKERTHREAD_H
