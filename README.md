# Network Traffic Analyzer



# Description
This project is designed to capture network packets for later analysis. This project uses functionality from the pcap.h library and Win32 API to work with the Windows operating system.

## Instalation

First you need to clone the project onto your computer
```
git clone https://gitlab.cs.taltech.ee/nbudov/network-protocol-analyzer.git
```

Use the cd command to navigate to the directory containing your CMake project.
```
cd network-protocol-analyzer
```

It's a good practice to create a separate directory for building the project. This keeps the source directory clean. For example:
```
mkdir build
cd build
```

Run CMake to generate the build files. Specify the path to the source directory using ..:
```
cmake ..
```
After it build our project:
```
cmake --build .
```

## Tools for capturing

To capture a data packets you need to use this command:
```
trff d --device_name
```

Where --device_name should be replaced with the name of the network adapter.

To find the device names you can use the command:
```
trff fd
```

which displays the names of all network adapters on your computer.

You can also capture packets over a period of time 
for this you can use the catch=duration command, 
where duration is the number of seconds you entered to capture. For example:

```
trff d catch=10 --device_name
```

where within 10 seconds the data will be written to the log.txt file
