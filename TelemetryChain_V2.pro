QT += core
QT -= gui
QT += network

CONFIG += c++11
CONFIG += c++11 console
CONFIG -= app_bundle

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

win32 {
INCLUDEPATH += C:\Users\olorl\Downloads\Npcap\Include
#LIBS += "-LC:\Users\olorl\Downloads\Npcap\Lib" -lwpcap -lpacket
LIBS += "-LC:\Users\olorl\Downloads\Npcap\Lib\x64" -lwpcap -lpacket
LIBS += -lws2_32

DEFINES += NPCAP
DEFINES += HAVE_REMOTE
}

linux-g++ | linux-g++-64 | linux-g++-32 {
LIBS += -lpcap
}

SOURCES += \
        dispatcher.cpp \
        main.cpp \
        workerthread.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    dispatcher.h \
    workerthread.h
