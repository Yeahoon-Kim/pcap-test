# pcap-test
## Objective
* Make code for capturing TCP/IP packet and print main information
## Component
* pcap-test.h
    * provide several APIs related to capturing packets
## Requirements
* Write the programs using C/C++ programming language
* Use libnet header in libnet library described below
    * pcap_findalldevs
    * pcap_compile
    * pcap_setfilter
    * pcap_lookupdev
    * pcap_loop
* Don't use APIs in pcap.h 
* Print list
    * source MAC / destination MAC in Ethernet header
    * source IP / destination IP in IP header
    * source port / destination port in TCP Header
    * first 8 bytes of hexadecimal values in payload
## Referenced Sites
* https://www.tcpdump.org/pcap.html
* https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test
* http://manual.freeshell.org/libnet11/html/libnet-headers_8h-source.html