#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>	// struct ether_header
//#include <netinet/ip.h>	// struct ip
#include <linux/ip.h>		// struct iphdr
#include <arpa/inet.h>		// inet_ntoa
#include <linux/tcp.h>		// tcphdr


void usage();

void print(struct pcap_pkthdr *header, const u_char *packet);
int  print_mac(const u_char *packet);
void print_ip(const u_char *packet);
void print_port(const u_char *packet);
void print_data(struct pcap_pkthdr *header,const u_char *packet);


int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);

	if (res == 0) continue;
		if (res == -1 || res == -2) break;

		print(header, packet);
	}

	pcap_close(handle);
 	return 0;
}


void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void print(struct pcap_pkthdr *header, const u_char *packet) {
	int type;
	puts("\n======== ================");
	printf("%8u bytes captured\n", header->caplen);

	type = print_mac(packet);
	if(type == 0x0800) {
		print_ip(packet);
		print_port(packet);
		print_data(header, packet);
	}
}

int print_mac(const u_char *packet) {
	struct ether_header *h_eth = (struct ether_header *)packet;
	int i;

	printf("MAC\t: %02x", h_eth->ether_shost[0]);
	for(i = 1; i < 6; i++)
		printf(":%02x", h_eth->ether_shost[i]);
	printf(" -> %02x", h_eth->ether_dhost[0]);
	for(i = 1; i < 6; i++)
		printf(":%02x", h_eth->ether_dhost[i]);
	printf("\n");
	return ntohs(h_eth->ether_type);
}

void print_ip(const u_char *packet) {
	struct iphdr *h_ip = (struct iphdr *)(packet + sizeof(struct ether_header));
	char *s_ip = inet_ntoa(*(struct in_addr *)&h_ip->saddr);
	char *d_ip = inet_ntoa(*(struct in_addr *)&h_ip->daddr);
	/* case 1 */
	printf("IP\t: %s ->", inet_ntoa(*(struct in_addr *)&h_ip->saddr));
	printf(" %s\n", inet_ntoa(*(struct in_addr *)&h_ip->daddr));
	/* case 2 */
	//printf("IP\t: %s -> %s\n", inet_ntoa(h_ip->ip_src), inet_ntoa(h_ip->ip_dst));
	// There is some error that i can't figure out the difference between those two things.
}

void print_port(const u_char *packet) {
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	printf("PORT\t: %d -> %d\n", ntohs(tcph->source), ntohs(tcph->dest));
}

void print_data(struct pcap_pkthdr *header, const u_char *packet) {
	struct iphdr *h_ip = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct tcphdr *h_tcp = (struct tcphdr *)(h_ip + h_ip->ihl*4);
	unsigned char *data = (unsigned char *)(h_tcp + h_tcp->doff*4);
	int i = 0;

	printf("Data\t: %02x ", data[i++]);
	for(i;i<16;i++) {
		if (!(i%8))
			printf("\n\t  ");
		printf("%02x ", data[i]);

	}
}
