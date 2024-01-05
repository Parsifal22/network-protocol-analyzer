#include "top_file.h"

class PacketsCatcher
{
private:
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    u_int i;

public:
    PacketsCatcher(int argc, char** argv);

    void readerPackets();
};