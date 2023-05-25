#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>

#include "dns.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
// static void parsePacket(const unsigned char *packet, unsigned int len, struct NETWATCH_HEADER_T *nwHeader);

typedef struct
{
	uint16_t ID;
	uint16_t FLAGS;//QR(1),opcode(4),AA(1),TC(1),RD(1),RA(1),zero(3),rcode(4)
	uint16_t queCount;
	uint16_t ansRss;
	uint16_t authority;
	uint16_t additional;
}dnshdr;

struct NETWATCH_HEADER_T
{
    enum
    {
        TCP = 0,
        UDP  = 1,
        UNKNOWN = 0xFF
    } protpcol;
    struct in_addr ip;     /* source ip */
    unsigned int port;     /* source port */
    unsigned int dstport;  /* dst port */
    unsigned int seq;      /* TCP SEQ */
    unsigned int flag;     /* TCP flags */
    unsigned char *data;   /* The original data */
};

//以太网帧头
struct ethernet_header
{
    unsigned char ether_dhost[ETHER_ADDR_LEN];
    unsigned char ether_shost[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

//IP头
struct ip_header
{
    unsigned char ip_vhl;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1FFF
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src, ip_dst;
};

//TCP头
struct tcp_header
{
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned short tcp_flag;
    unsigned short tcp_w;
    unsigned short tcp_ck;
    unsigned short tcp_em;
};

//UDP头
struct udp_header
{
    unsigned short udp_sport;
    unsigned short udp_dport;
    unsigned short udp_len;
    unsigned short udp_sum;
};

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net, mask;

    // 获取默认网络接口
    // char *dev = pcap_lookupdev(errbuf);
    char *dev = "ens160";
    // printf("dev:%s\n", dev);
    // if (dev == NULL) {
    //     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    //     return 2;
    // }

    // 获取网络接口的IP地址和子网掩码
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 打开网络接口
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // // 编译过滤器表达式
    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return 2;
    // }

    // // 应用过滤器
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return 2;
    // }

    // 开始捕获数据包
    pcap_loop(handle, -1, packet_handler, NULL);

    // 关闭网络接口
    pcap_close(handle);

    return 0;
}

//解析包函数，未用到
static void parsePacket(const unsigned char *packet, unsigned int len, struct NETWATCH_HEADER_T *nwHeader)
{
    struct ethernet_header *pstEth = (struct ethernet_header *)packet;
    struct ip_header *pstIp = NULL;
    struct udp_header *pstUdp = NULL;
    struct tcp_header *pstTcp = NULL;

    if (0x0608 == pstEth->ether_type)
    {
        nwHeader->protpcol = UNKNOWN;
    }
    else if (0x0008 == pstEth->ether_type)
    {
        pstIp = (struct ip_header *)(pstEth + 1);
        nwHeader->ip = pstIp->ip_src;
        if (0x06 == pstIp->ip_p) /* TCP */
        {
            nwHeader->protpcol = TCP;
            pstTcp = (struct tcp_header *)(pstIp + 1);
            nwHeader->seq  = htonl(pstTcp->tcp_seq);
            nwHeader->port = htons(pstTcp->tcp_sport);
            nwHeader->dstport = htons(pstTcp->tcp_dport);
            nwHeader->flag = htons(pstTcp->tcp_flag);
            nwHeader->data = (unsigned char *)packet;
            //printf("TCP, src=%s:%d dst=%s:%d\n", inet_ntoa(pstIp->ip_src), pstTcp->tcp_sport, inet_ntoa(pstIp->ip_dst), pstTcp->tcp_dport);
        }
        else if (0x11 == pstIp->ip_p) /* UDP */
        {
            nwHeader->protpcol = UDP;
            pstUdp = (struct udp_header *)(pstIp + 1);
            nwHeader->port = htons(pstUdp->udp_sport);
            nwHeader->dstport = htons(pstUdp->udp_dport);
            nwHeader->data = (unsigned char *)packet;
            //printf("UDP, src=%s:%d dst=%s:%d\n", inet_ntoa(pstIp->ip_src), pstUdp->udp_sport, inet_ntoa(pstIp->ip_dst), pstUdp->udp_dport);
        }
        else
        {
            nwHeader->protpcol = UNKNOWN;
        }
    }
    else
    {
        nwHeader->protpcol = UNKNOWN;
    }

    return;
}

//处理报文的回调函数
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    // char sip[32] = {0};

    // struct NETWATCH_HEADER_T stNwHeader;
    // parsePacket(pkt_data, header->len, &stNwHeader);

    // if (stNwHeader.protpcol == UNKNOWN)
    // {
    //     return;
    // }
    
    // /* 53ΪDNS�˿� */
    // if (53 == stNwHeader.port)
    // {
    //     dns_check(pkt_data);
    // }

    // return;

    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    char *dns_hdr;
    char *query_name;
    int query_type;
    int query_class;
    int query_len;

    // 解析IP头部
    ip_hdr = (struct iphdr *)(pkt_data + sizeof(struct ether_header));
    if (ip_hdr->protocol != IPPROTO_UDP) {
        return;
    }

    // 解析UDP头部
    udp_hdr = (struct udphdr *)(pkt_data + sizeof(struct ether_header) + sizeof(struct iphdr));
    if (ntohs(udp_hdr->dest) != 53) {
        return;
    }

    // 解析DNS头部
    dns_hdr = (char *)(pkt_data + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    query_name = dns_hdr + sizeof(dnshdr);
    query_type = ntohs(*(unsigned short *)(dns_hdr + sizeof(dnshdr) + strlen(query_name) + 1));
    query_class = ntohs(*(unsigned short *)(dns_hdr + sizeof(dnshdr) + strlen(query_name) + 3));
    query_len = sizeof(dnshdr) + strlen(query_name) + 5;

    // 输出DNS查询信息
    printf("DNS query: %s %d %d\n", query_name, query_type, query_class);
    dns_check(pkt_data);
}
