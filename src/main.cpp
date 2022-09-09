#include "pcap-test.h"

using namespace std;

pcap_t* pcap;

void InterruptHandler(const int signo) {
    if(signo == SIGINT) {
        cout << "Keyboard Interrupt" << endl;
		if(pcap != NULL) pcap_close(pcap);
		exit(0);
    }
}

int main(int argc, char* argv[]) {
	signal(SIGINT, InterruptHandler);	// signal handler

	if (argc != 2) {
		cerr << "Error: Wrong parameters are given\n";
		cerr << "syntax: pcap-test <interface>\n";
		cerr << "sample: pcap-test wlan0" << endl;

		return 1;
	}

	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res, flag;

	dev = argv[1];
	pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		cerr << "Error: Error while open device ";
		cerr << errbuf << endl;

		return 1;
	}

	while (true) {
		res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			cout << "Error : Error while pcap_next_ex: ";
			cout << pcap_geterr(pcap) << endl;

			break;
		}
		
		flag = printPacket(packet);

		switch(flag) {
			case FAILURE_NOT_TCP: cout << "The packet captured is not a TCP\n"; break;
			case FAILURE_NOT_IP: cout << "The packet captured is not a IP\n"; break;
			case SUCCESS: cout << "Successfully captured packet\n"; break;
			default: break;
		}
	}

	pcap_close(pcap);

	return 0;
}
