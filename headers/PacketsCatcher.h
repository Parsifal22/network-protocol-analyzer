#include "top_file.h"

class PacketsCatcher
{
private:
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int catchDuration = 0;


public:
    PacketsCatcher();

    void findDevices();

    int openDevice(char * device_name);

    void catchTraffic();

    inline void setCatchDuration(int duration) { catchDuration = duration; }
};