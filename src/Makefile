CC = g++
CFLAGS = -W -Wall
OBJECTS = ./pcap-test.o ./main.o
TARGET = ../bin/pcap-test
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(@) $(OBJECTS) $(LIBS)

main.o: ./pcap-test.hpp ./pcap-test.cpp ./main.cpp
pcap-test.o: ./pcap-test.hpp ./pcap-test.cpp

clean:
	rm -f ../bin/$(TARGET)
	rm -f *.o

.PHONY: all clean