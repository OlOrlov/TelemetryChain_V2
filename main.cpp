#include <QCoreApplication>
#include "dispatcher.h"

#if defined(Q_OS_WIN)
void ifprint(pcap_if_t* d)
{
    pcap_addr_t *a;

    printf("%s\n",d->name);	//Name

    if (d->description)
    {
        printf("Description: %s\n",d->description);	//Description
    }

    // Loopback Address
    printf("Loopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"Yes":"No");

    for(a = d->addresses; a; a=a->next)	//Now print the IP addresses etc of each device
    {
        printf("Address Family: #%d\n",a->addr->sa_family);

        switch(a->addr->sa_family)
        {
            case AF_INET:
                printf("Address Family Name: AF_INET\n");

                if (a->addr)
                {
                    printf("Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
                }

                if (a->netmask)
                {
                    //If a valid netmask has been detected
                    printf("Netmask: %s\n",inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
                }

                if (a->broadaddr)
                {
                    //If a valid Broadcast Address is detected
                    printf("Broadcast Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
                }

                if (a->dstaddr)
                {
                    printf("Destination Address: %s\n",inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr));
                }
            break;

            default:
                printf("Address Family Name: Unknown\n");
                break;
        }
    }
    printf("\n");
}
#endif

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    #if defined(Q_OS_LINUX) || defined(Q_OS_UNIX)
        if (argc<1)
        {
            fprintf(stderr,"usage: <interface>\n");
            exit(1);
        }
        Dispatcher dispatcher(argv[1]);

    #elif defined(Q_OS_WIN)
        pcap_addr_t* addr;
        pcap_if_t* alldevs , *d , dev[100];
        int count = 1;
        char errbuf[257];
        printf("Retrieving the available devices...");

        if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
            exit(1);
        }
        printf("Retrieved.\n");

        printf("The following devices found : \n\n");
        for(d = alldevs ; d ; d = d->next)	//Print the devices
        {
            printf("%d)\n",count);
            dev[count++] = *d;
            ifprint(d);
        }

        //Ask user to select the device he wants to use
        printf("Enter the device number you want to use : ");
        scanf("%d",&count);

        addr = dev[count].addresses;

        Dispatcher dispatcher(dev[count].name);
    #endif

    return a.exec();
}
