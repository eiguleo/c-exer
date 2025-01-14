#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>


uint16_t ip_checksum(uint16_t *buf, int len) {
    unsigned long sum;
    sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

void assemble_eth_frame(char *buffer, const unsigned char *src_mac, const unsigned char *dest_mac, const struct iphdr *ip_hdr) {
    struct ethhdr *eth_hdr = (struct ethhdr *)buffer;

    // 填充以太网帧头
    memcpy(eth_hdr->h_dest, dest_mac, ETH_ALEN);
    memcpy(eth_hdr->h_source, src_mac, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_IP);

    // 将IP报文头部复制到缓冲区
    memcpy(buffer + sizeof(struct ethhdr), ip_hdr, sizeof(struct iphdr));
}

void parse_eth_frame(const char *buffer) {
    struct ethhdr *eth_hdr = (struct ethhdr *)buffer;

    printf("Source MAC: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_hdr->h_source[i]);
        if (i < ETH_ALEN - 1) printf(":");
    }
    printf("\n");

    printf("Destination MAC: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_hdr->h_dest[i]);
        if (i < ETH_ALEN - 1) printf(":");
    }
    printf("\n");

    printf("Ethernet Type: 0x%04x\n", ntohs(eth_hdr->h_proto));

    if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {
        struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        printf("Source IP: %d.%d.%d.%d\n", (ip_hdr->saddr >> 24) & 0xFF, (ip_hdr->saddr >> 16) & 0xFF, (ip_hdr->saddr >> 8) & 0xFF, ip_hdr->saddr & 0xFF);
        printf("Destination IP: %d.%d.%d.%d\n", (ip_hdr->daddr >> 24) & 0xFF, (ip_hdr->daddr >> 16) & 0xFF, (ip_hdr->daddr >> 8) & 0xFF, ip_hdr->daddr & 0xFF);
        printf("IP Protocol: %d\n", ip_hdr->protocol);
        printf("IP Total Length: %d\n", ntohs(ip_hdr->tot_len));
    }
}

int main() {
    char buffer[2048];
    unsigned char src_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char dest_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    struct iphdr ip_hdr;
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.ihl = 5;  // IP头长度（5 * 4 = 20字节）
    ip_hdr.version = 4;  // IP版本（IPv4）
    ip_hdr.tos = 0;  // 服务类型
    ip_hdr.tot_len = htons(sizeof(struct iphdr));  // 总长度
    ip_hdr.id = htons(12345);  // 标识
    ip_hdr.frag_off = 0;  // 片偏移
    ip_hdr.ttl = 64;  // 生存时间
    ip_hdr.protocol = IPPROTO_RAW;  // 协议类型（原始协议）
    ip_hdr.check = 0;  // 校验和（先设为0，后面计算）
    ip_hdr.saddr = inet_addr("192.168.1.100");  // 源IP地址
    ip_hdr.daddr = inet_addr("8.8.8.8");  // 目标IP地址

    // 计算IP校验和
    ip_hdr.check = ip_checksum((uint16_t *)&ip_hdr, sizeof(ip_hdr));

    // 组装以太网帧
    assemble_eth_frame(buffer, src_mac, dest_mac, &ip_hdr);

    // 解析以太网帧
    parse_eth_frame(buffer);

    return 0;
}
