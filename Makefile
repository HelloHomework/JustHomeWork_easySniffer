all: readPcap.c
	gcc readPcap.c -lpcap -o readPcap
clean: readPcap
	rm readPcap