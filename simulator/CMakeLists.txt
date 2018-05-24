cmake_minimum_required(VERSION 3.9)
project(pcap)

set(CMAKE_CXX_STANDARD 11)

add_executable(pcap
        lib/everflow.c
        include/everflow.h
        lib/hash.c
        include/hash.h
        lib/keytracker.c
        include/keytracker.h
        main.c
        lib/motivation.c
        include/motivation.h
        lib/netsight.c
        include/netsight.h
        lib/packet.c
        include/packet.h
        include/protocol.h
        lib/sample.c
        include/sample.h
        include/key.h)

include_directories(./include/)

include_directories(C:\\libpcap-1.8.1)