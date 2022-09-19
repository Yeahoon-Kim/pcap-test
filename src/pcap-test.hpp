#pragma once

#include <iostream>     // cin, sout, hex, dec, ...
#include <sstream>      // stringstream
#include <cstring>      // memcpy
#include <string>       // string
#include <iomanip>      // setw, setfill
#include <pcap.h>       // pcap_open_live, ...
#include <arpa/inet.h>  // inet_ntoa
#include "libnet.hpp"

#define FAILURE_NOT_TCP -1
#define FAILURE_NOT_IP -2
#define SUCCESS 0

void findEthHeader(struct libnet_ethernet_hdr& eth, const u_char* packet);

void findTCPHeader(struct libnet_tcp_hdr& tcp, const u_char* packet);

void findIPHeader(struct libnet_ipv4_hdr& ipv4, const u_char* packet);

int printPacket(const u_char* packet);