#include "PacketsCatcher.h"


PacketsCatcher::PacketsCatcher() : fp(nullptr), res(0) {}


int PacketsCatcher::openDevice(char* device_name) 
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
        std::cout << ERROR << errbuf << RESET << std::endl;
        return -1;
    }

    std::cout << "\033[38;5;29m" << "Device open successfully!\n" << RESET << std::endl;
    return 0;
}


void PacketsCatcher::findDevices()
{
    u_int i = 0;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        std::cerr << ERROR << "Error in pcap_findalldevs_ex: \n" << errbuf << RESET << std::endl;
    }
    else
    {
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
            std::cerr << ERROR << "No interfaces found! Exiting." << RESET << std::endl;

        }

        }


}


void PacketsCatcher::catchTraffic()
{


    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    
    /* Read the packets */
    if (catchDuration == 0) 
    {
        while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
        {    
            if (res == 0)
                /* Timeout elapsed */
                continue;

            /* print pkt timestamp and pkt len */
            std::cout << header->ts.tv_sec << ":" << header->ts.tv_usec << " (" << header->len << ")" << std::endl;

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
            std::cerr << ERROR << "Error reading the packets: " << pcap_geterr(fp) << RESET << std::endl;
          
        }
    }
    else 
    {
        std::ofstream logFile("log.txt");

        auto startTime = std::chrono::high_resolution_clock::now();
        auto endTime = startTime + std::chrono::seconds(catchDuration);

        while (std::chrono::high_resolution_clock::now() < endTime && (res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
        {
            if (res == 0)
                /* Timeout elapsed */
                continue;

            /* print pkt timestamp and pkt len to console */
            std::cout << header->ts.tv_sec << ":" << header->ts.tv_usec << " (" << header->len << ")" << std::endl;

            /* write pkt timestamp and pkt len to log file */
            logFile << header->ts.tv_sec << ":" << header->ts.tv_usec << " (" << header->len << ")" << std::endl;

            /* Print the packet to console and log file */
            for (u_int i = 1; (i < header->caplen + 1); i++)
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]) << " ";
                if ((i % LINE_LEN) == 0)
                    std::cout << "\n";

                // write packet data to log file
                logFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]) << " ";
                if ((i % LINE_LEN) == 0)
                    logFile << "\n";
            }

            std::cout << "\n\n";
            logFile << std::endl << std::endl;
        }

        // Close the log file
        logFile.close();

        // Clear variable catchDuration
        catchDuration = 0;

        if (res == -1)
        {
            std::cerr << ERROR << "Error reading the packets: " << pcap_geterr(fp) << RESET << std::endl;
        }

    }

}

