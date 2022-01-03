all: easySniffer.c
	gcc easySniffer.c -lpcap -o easySniffer
clean: easySniffer
	rm easySniffer
