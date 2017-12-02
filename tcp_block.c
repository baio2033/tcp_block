#include "tcp_block.h"

void print_mac(u_char* mac){
	for(int i=0;i<6;i++){
		if(i!=5)
			printf("%02X:",mac[i]);
		else
			printf("%02X\n",mac[i]);
	}
	printf("\n");
}

void packet_dump(u_char* packet, int packet_len){	
	for(int i=0;i<packet_len;i++){
		if(i!=0 && i%16==0)
			printf("\n");
		printf("%02X ",packet[i]);
	}
	printf("\n");
}

u_int16_t ip_sum_calc( u_int16_t len_ip_header, u_int16_t * buff )
{
        u_int16_t word16;
        u_int sum = 0;
        u_int16_t i;
        // make 16 bit words out of every two adjacent 8 bit words in the packet
        // and add them up
        for( i = 0; i < len_ip_header; i = i+2 )
        {
                word16 = ( ( buff[i]<<8) & 0xFF00 )+( buff[i+1] & 0xFF );
                sum = sum + (u_int) word16;
        }
        // take only 16 bits out of the 32 bit sum and add up the carries
        while( sum >> 16 )
                sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        // one's complement the result
        sum = ~sum;
       
        return ((u_int16_t) sum);
}

u_int16_t tcp_checksum(u_int16_t *buf, int len){
	u_long sum = 0;
	while(len--){
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (u_int16_t)(~sum);
}

void make_rst_etherhdr(struct etherhdr *ether, struct etherhdr *rst_ether){	
	memcpy(rst_ether->dst,ether->src,sizeof(ether->dst));
	memcpy(rst_ether->src,ether->dst,sizeof(ether->src));
	rst_ether->ether_type = ether->ether_type;
}

void make_rst_iphdr(struct iphdr *ip, struct iphdr *rst_ip){
	memcpy(rst_ip, ip, sizeof(struct iphdr));
	rst_ip->ip_len = htons(54)	;
	memcpy(&rst_ip->ip_src, &ip->ip_dst, sizeof(ip->ip_dst));
	memcpy(&rst_ip->ip_dst, &ip->ip_src, sizeof(ip->ip_src));
	rst_ip->ip_sum = 0;
}

void make_rst_tcphdr(struct tcp_header *tcp, struct tcp_header *rst_tcp, int flag){
	memcpy(rst_tcp, tcp, sizeof(struct tcp_header));
	memcpy(&rst_tcp->tcp_src, &tcp->tcp_dst, sizeof(tcp->tcp_dst));
	memcpy(&rst_tcp->tcp_dst, &tcp->tcp_src, sizeof(tcp->tcp_src));

	rst_tcp->tcp_off = 5;

	if(rst_tcp->tcp_src == ntohs(0x50) || rst_tcp->tcp_dst == ntohs(0x50))
		rst_tcp->tcp_flag = 0x11;
	else
		rst_tcp->tcp_flag = 0x14;

	if(flag > 0){
		rst_tcp->tcp_seq = tcp->tcp_ack;
		rst_tcp->tcp_ack = tcp->tcp_seq + flag;
	}
	else{
		rst_tcp->tcp_seq = tcp->tcp_ack;
		rst_tcp->tcp_ack = tcp->tcp_seq + 1;
	}
}

void check_packet(pcap_t *handle, u_char *packet, int packet_len){
	struct etherhdr *recv_ether, *rst_ether;
	struct iphdr *recv_iphdr, *rst_iphdr;
	struct tcp_header *recv_tcp, *rst_tcp;
	u_char *rst_packet;
	int flag, header_len;
	int ether_size = sizeof(struct etherhdr);
	int ip_size = sizeof(struct iphdr);
	int tcp_size = sizeof(struct tcp_header);
	int mode;

	struct pseudohdr pheader;

	recv_ether = (struct ehterhdr *)packet;	
	if(ntohs(recv_ether->ether_type) != ETHERTYPE_IP) return;
	recv_iphdr = (struct iphdr *)(packet + sizeof(struct etherhdr));	
	if(recv_iphdr->ip_p != 0x06) return;	
	recv_tcp = (struct tcp_header *)(packet + sizeof(struct etherhdr) + sizeof(struct iphdr));

	header_len = sizeof(struct etherhdr) + sizeof(struct iphdr) + sizeof(struct tcp_header);
	flag = packet_len - header_len;
	if(flag == 0) flag = 1;

	rst_ether = (struct etherhdr *)malloc(sizeof(struct etherhdr));
	rst_iphdr = (struct iphdr *)malloc(sizeof(struct iphdr));
	rst_tcp = (struct tcp_header *)malloc(sizeof(struct tcp_header));

	//printf("data length : %d\n", flag);
	make_rst_etherhdr(recv_ether, rst_ether);	
	make_rst_iphdr(recv_iphdr, rst_iphdr);
	rst_iphdr->ip_sum = ip_sum_calc(ip_size, rst_iphdr);	
	make_rst_tcphdr(recv_tcp, rst_tcp, flag);	

	pheader.src.s_addr = rst_iphdr->ip_src.s_addr;
	pheader.dst.s_addr = rst_iphdr->ip_dst.s_addr;
	pheader.protocol = rst_iphdr->ip_p;
	pheader.len = htons(sizeof(struct tcp_header)+packet_len - header_len);

	rst_tcp->tcp_sum = tcp_checksum((u_int16_t*)&pheader, sizeof(struct pseudohdr) / sizeof(u_int16_t));

	rst_packet = (u_char*)malloc(packet_len);
	memcpy(rst_packet, rst_ether, ether_size);
	memcpy(rst_packet + ether_size, rst_iphdr, ip_size);
	memcpy(rst_packet + ether_size + ip_size, rst_tcp, tcp_size);

	printf("========================================================\n");
	printf("\t\tOriginal packet\n");
	packet_dump(packet, header_len);
	printf("\t\tRST packet\n");
	packet_dump(rst_packet, header_len);

	while(1){
		if(pcap_sendpacket(handle, rst_packet, header_len) == 0) {
			printf("\n[+] Send RST packet!\n");			
			break;
		}
	}

	free(rst_ether);
	free(rst_iphdr);
	free(rst_tcp);
}

int main(int argc, char *argv[]){
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_char *packet, *recv_packet;
	u_char *dev, errbuf[PCAP_ERRBUF_SIZE];
	int ret;

	if(argc < 2){
		printf("[+] Usage : %s <interface>\n", argv[0]);
		exit(1);
	}

	dev = argv[1];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if(handle == NULL){
		printf("\n[-] fail to open device\n");
		exit(1);
	}
	if(pcap_datalink(handle) != DLT_EN10MB){
		printf("\n[-] device do not provide ethernet\n");
		exit(1);
	}

	int cnt = 0;
	while(1){
		ret = pcap_next_ex(handle, &header, &packet);
		if(ret == 0){
			//printf("[-] time out...\n");
			continue;
		}
		else if(ret < 0){
			printf("[-] fail to receive packet!\n");
			break;
		}
		else{
			//printf("#################################################\n");
			//printf("\t\t[ %d frame ] ( legnth : %d )\n",cnt++, header->len);			
			//packet_dump(packet, header->len);
			check_packet(handle, packet, header->len);
		}
	}

}