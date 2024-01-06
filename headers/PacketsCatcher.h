#include "top_file.h"

class PacketsCatcher
{
private:
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    pcap_if_t* alldevs;
    pcap_if_t* d;

public:
    PacketsCatcher();

    void findDevices();

    void openDevice(char * device_name);

    void frameReader();
};