CPP=g++
CPPFLAGS=-std=c++11 -pedantic

all: ipk-scan

ipk-scan: ipk-scan.cpp
	$(CPP) $(CPPFLAGS)  ipk-scan.cpp Ports.h Sockets.h -lpcap -o ipk-scan

clean:
	rm -f *.o
