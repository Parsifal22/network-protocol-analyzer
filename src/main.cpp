/*
  The functionality for the findDevices, openDevice and catchTraffic 
  methods was taken and modified from the source: https://www.winpcap.org/docs/docs_412/html/group__wpcapsamps.html 
 */


#include "top_file.h"
#include "PacketsCatcher.h"


int main(int argc, char** argv)
{
 
    PacketsCatcher pc = PacketsCatcher();


    if (strcmp(argv[1], "fd") == 0)
    {
        pc.findDevices();
    }
    else if (strcmp(argv[1], "d") == 0)
    {
        if (argc < 3) 
        {
            std::cout << "\nPlease indicate the device name" << std::endl;
            std::cout << "You can use \"fd\" function to get list of available devices" << std::endl;
            return -1;
        }
        else 
        {
            if (argc > 3) 
            {
                if (std::strstr(argv[2], "catch=") != nullptr)
                {
                    int durationValue;

                    if (sscanf_s(argv[2], "catch=%d", &durationValue) == 1) {
                        pc.setCatchDuration(durationValue);
                    }
                    else {
                        std::cout << ERROR << "Error: unable to read catch value" << RESET << std::endl;
                        return -1;
                    }
                }
                else
                {
                    std::cout << ERROR << "Error: the comand " << argv[2] << " doesn't exist" << RESET << std::endl;
                    return -1;
                }
                
            }

            if (pc.openDevice(argv[argc - 1]) >= 0)
            {
                pc.catchTraffic();
            }

 
                
        }

    }

    return 0;
}
