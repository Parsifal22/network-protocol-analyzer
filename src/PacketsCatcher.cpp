#include "PacketsCatcher.h"


PacketsCatcher::PacketsCatcher(int argc, char** argv)
{
    pcap_if_t* alldevs, * d;
    u_int inum, i = 0;

    if (argc < 3)
    {
        std::cout << "\nNo adapter selected: printing the device list:\n";
        /* The user didn't provide a packet source: Retrieve the local device list */
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << "\n";
            return;
        }

        /* Print the list */
        for (d = alldevs; d; d = d->next)
        {
            std::cout << ++i << ". " << d->name << "\n    ";
            if (d->description)
                std::cout << " (" << d->description << ")\n";
            else
                std::cout << " (No description available)\n";
        }

        if (i == 0)
        {
            std::cerr << "No interfaces found! Exiting.\n";
            return;
        }

        std::cout << "Enter the interface number (1-" << i << "):";
        std::cin >> inum;

        if (inum < 1 || inum > i)
        {
            std::cout << "\nInterface number out of range.\n";

            /* Free the device list */
            pcap_freealldevs(alldevs);
            return;
        }

        /* Jump to the selected adapter */
        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        /* Open the device */
        if ((fp = pcap_open(d->name,
            100 /*snaplen*/,
            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
            20 /*read timeout*/,
            NULL /* remote authentication */,
            errbuf)
            ) == NULL)
        {
            std::cerr << "\nError opening adapter\n";
            return;
        }
    }
    else
    {
        // Do not check for the switch type ('-s')
        if ((fp = pcap_open(argv[2],
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
}



void PacketsCatcher::readerPackets()
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

