#include "PacketsCatcher.h"


PacketsCatcher::PacketsCatcher() : fp(nullptr), res(0) {}

void PacketsCatcher::openDevice(char* device_name) 
{
        // Do not check for the switch type ('-s')
        if ((fp = pcap_open(device_name,
            100 /*snaplen*/,
            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
            20 /*read timeout*/,
            NULL /* remote authentication */,
            errbuf)
            ) == NULL)
        {
            std::cerr << "\nError opening source: " << errbuf << "\n";
            return;
        }
}


void PacketsCatcher::findDevices()
{
    u_int i = 0;

        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
            return;
        }

        /* Print the list */
        for (d = alldevs; d; d = d->next)
        {
            
            std::cout << ++i << ". " << d->name << std::endl << "\t";
            if (d->description)
                std::cout << " (" << d->description << ")" << std::endl;
            else
                std::cout << " (No description available)" << std::endl;
        }

        if (i == 0)
        {
            std::cerr << "No interfaces found! Exiting.\n";
            return;
        }


}


void PacketsCatcher::frameReader()
{
    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    /* Read the packets */
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        std::cout << header->ts.tv_sec << ":" << header->ts.tv_usec << " (" << header->len << ")\n";

        /* Print the packet */
        for (u_int i = 1; (i < header->caplen + 1); i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]) << " ";
            if ((i % LINE_LEN) == 0)
                std::cout << "\n";
        }

        std::cout << "\n\n";
    }

    if (res == -1)
    {
        std::cerr << "Error reading the packets: " << pcap_geterr(fp) << "\n";
        return;
    }
}

