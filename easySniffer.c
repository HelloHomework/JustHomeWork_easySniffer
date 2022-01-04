#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int packetCount = 0;
int icmpCount = 0;
int tcpCount = 0;
int udpCount = 0;
int arpCount = 0;
int dnsCount = 0;
int httpCount = 0;
int bootpCount = 0;

void packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void usage();

int main(int argc, char* argv[]) {
  pcap_t* fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  char source[PCAP_BUF_SIZE];
  int limit = -1;
  int returnValue = 0;

  if (argc < 3) {
    usage();
    return 0;
  }

  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t* pcap;

  if (strcmp(argv[1], "-1") == 0) {
    pcap_if_t* devices = NULL;
    if (pcap_findalldevs(&devices, errbuf) == -1) {
      fprintf(stderr, "pcap_lookupdev failed: %s\n", errbuf);
      exit(1);
    }  // end if
    printf("Sniffing: %s\n", devices->name);
    pcap = pcap_open_live(devices->name, 65535, 1, 1, errbuf);
  } else {
    pcap = pcap_open_offline(argv[1], errbuff);
  }
  limit = atoi(argv[2]);

  struct pcap_pkthdr* header;
  const u_char* data;

  while (1) {
    int returnValue = pcap_next_ex(pcap, &header, &data);
    // no more packet
    if (returnValue == 1) {
      packetHandler(header, data);
    } else if (returnValue == -1) {
      fprintf(stderr, "pcap_next_ex() failed: %s\n", pcap_geterr(pcap));
    }  // failed
    else if (returnValue == -2) {
      printf("File End\n");
      break;
    }  // end if read no more packet
    if (packetCount == limit) break;
  }
  pcap_close(pcap);

  printf("=====================Summary=====================\n");
  printf("%d ARP packets,%d ICMP packets, %d TCP packets, %d UDP packets\n",
         arpCount, icmpCount, tcpCount, udpCount);
  printf("%d DNS packets, %d HTTPS/HTTP packets\n", dnsCount, httpCount);
  printf("%d bootp/dhcp packets\n", bootpCount);
  printf("=================================================\n");
  return 0;
}

void usage() {
  printf("Usage\n");
  printf("./easySniffer filename num\n");
  printf("filename : pcap file, -1 mean auto capture device\n");
  printf("num : capture the packet not more than [num], -1 no limit\n");
}

void packetHandler(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader = (struct ether_header*)packet;

  printf("===== Packet %d =====\n", ++packetCount);
  printf("Packet size: %d bytes\n", pkthdr->len);
  if (pkthdr->len != pkthdr->caplen)
    printf("Warning! Capture size different than packet size: %u bytes\n",
           pkthdr->len);
  printf("SrcMacAddress %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
         ethernetHeader->ether_shost[0], ethernetHeader->ether_shost[1],
         ethernetHeader->ether_shost[2], ethernetHeader->ether_shost[3],
         ethernetHeader->ether_shost[4], ethernetHeader->ether_shost[5]);
  printf("DstMacAddress %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
         ethernetHeader->ether_dhost[0], ethernetHeader->ether_dhost[1],
         ethernetHeader->ether_dhost[2], ethernetHeader->ether_dhost[3],
         ethernetHeader->ether_dhost[4], ethernetHeader->ether_dhost[5]);

  printf("Epoch Time: %ld:%d seconds\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
  if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
    const struct ip* ipHeader =
        (struct ip*)(packet + sizeof(struct ether_header));
    u_int srcPort, dstPort;
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
    printf("srcIP %s\n", srcIP);  // tcphdr->source
    printf("dstIP %s\n", dstIP);  // tcphdr->dest

    if (ipHeader->ip_p == IPPROTO_TCP) {
      printf("Type TCP\n");
      tcpCount = tcpCount + 1;
      const struct tcphdr* tcpHeader =
          (struct tcphdr*)(packet + sizeof(struct ether_header) +
                           sizeof(struct ip));
      srcPort = ntohs(tcpHeader->th_sport);
      dstPort = ntohs(tcpHeader->th_dport);
      printf("srcPort: %d\n", srcPort);
      printf("srcPort: %d\n", dstPort);

      // TCP FLAG
      if (tcpHeader->th_flags & TH_FIN) {
        printf("TCP FLAG : FIN\n");
      } else if (tcpHeader->th_flags & TH_SYN) {
        printf("TCP FLAG : SYN\n");
      } else if (tcpHeader->th_flags & TH_RST) {
        printf("TCP FLAG : RST\n");
      } else if (tcpHeader->th_flags & TH_PUSH) {
        printf("TCP FLAG : PUSH\n");
      } else if (tcpHeader->th_flags & TH_ACK) {
        printf("TCP FLAG : ACK\n");
      } else if (tcpHeader->th_flags & TH_URG) {
        printf("TCP FLAG : URG\n");
      } else if (tcpHeader->th_flags & TH_ECE) {
        printf("TCP FLAG : ECE\n");
      } else if (tcpHeader->th_flags & TH_CWR) {
        printf("TCP FLAG : CWR\n");
      }
      if (srcPort == 80 || srcPort == 443 || dstPort == 80 || dstPort == 443) {
        httpCount++;
      }

      if (srcPort == 53 || dstPort == 53) {
        dnsCount = dnsCount + 1;
      }

    } else if (ipHeader->ip_p == IPPROTO_UDP) {
      printf("Type UDP\n");
      udpCount = udpCount + 1;
      const struct udphdr* udpHeader =
          (struct udphdr*)(packet + sizeof(struct ether_header) +
                           sizeof(struct ip));
      srcPort = ntohs(udpHeader->uh_sport);
      dstPort = ntohs(udpHeader->uh_dport);

      if (srcPort == 53 || dstPort == 53) {
        dnsCount = dnsCount + 1;
      }

      if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) {
        bootpCount = bootpCount + 1;
      }
    } else if (ipHeader->ip_p == IPPROTO_ICMP) {
      printf("Type ICMP\n");
      icmpCount = icmpCount + 1;
    } else {
      printf("Type %d\n", ipHeader->ip_p);
    }
  } else if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
    printf("type ARP\n");
    arpCount++;
  } else {
    printf("Other Type packets\n");
    printf("%d",ntohs(ethernetHeader->ether_type));
  }
  printf("=====================\n\n");
}
