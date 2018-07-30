#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>	// struct ether_header
#include <netinet/ip.h>		// struct ip
//#include <linux/ip.h>		// struct iphdr
#include <arpa/inet.h>		// inet_ntoa
#include <linux/tcp.h>		// tcphdr


void usage();

void print(struct pcap_pkthdr *header, const u_char *packet);
void print_mac(const u_char *packet);
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
	puts("\n======== ================");
	printf("%5u bytes captured\n", header->caplen);

	print_mac(packet);
	print_ip(packet);
	print_port(packet);
	print_data(header, packet);
}

void print_mac(const u_char *packet) {
	struct ether_header *ethhdr = (struct ether_header *)packet;
	int i;

	printf("MAC\t: %02x", ethhdr->ether_shost[0]);
	for(i = 1; i < 6; i++)
		printf(":%02x", ethhdr->ether_shost[i]);
	printf(" -> %02x", ethhdr->ether_dhost[0]);
	for(i = 1; i < 6; i++)
		printf(":%02x", ethhdr->ether_dhost[i]);
	printf("\n");
}

void print_ip(const u_char *packet) {
	struct ip *h_ip = (struct ip *)(packet + sizeof(struct ether_header));
	char *s_ip = inet_ntoa(h_ip->ip_src);
	char *d_ip = inet_ntoa(h_ip->ip_dst);
	/* case 1 */
	printf("IP\t: %s ->", inet_ntoa(h_ip->ip_src));
	printf(" %s\n", inet_ntoa(h_ip->ip_dst));
	/* case 2 */
	//printf("IP\t: %s -> %s\n", inet_ntoa(h_ip->ip_src), inet_ntoa(h_ip->ip_dst));
	// There is some error that i can't figure out the difference between those two things.
}

void print_port(const u_char *packet) {
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	printf("PORT\t: %d -> %d\n", ntohs(tcph->source), ntohs(tcph->dest));
}

void print_data(struct pcap_pkthdr *header, const u_char *packet) {
	unsigned char *data = (unsigned char *)(packet +
			sizeof(struct ether_header) +
			sizeof(struct iphdr) +
			sizeof(struct tcphdr));
	int i = 0;

	printf("Data\t: %02x ", data[i++]);
	for(i;i<16;i++) {
		if (!(i%8))
			printf("\n\t  ");
		printf("%02x ", data[i]);

	}
}
