#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // 防止用于发送数据包的txbuf(尚未缓存至arp_buf)被破坏而不使用txbuf
    buf_t *tbuf = (buf_t *)malloc(sizeof(buf_t));
    buf_init(tbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)tbuf->data;

    pkt->hw_type16 = constswap16(ARP_HW_ETHER);
    pkt->pro_type16 = constswap16(NET_PROTOCOL_IP);
    pkt->hw_len = NET_MAC_LEN;
    pkt->pro_len = NET_IP_LEN;
    pkt->opcode16 = constswap16(ARP_REQUEST);
    memcpy(pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(pkt->sender_ip, net_if_ip, NET_IP_LEN);
    memset(pkt->target_mac, 0, NET_MAC_LEN);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    buf_add_padding(tbuf, ETHERNET_MIN_TRANSPORT_UNIT - sizeof(arp_pkt_t));

    ethernet_out(tbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
    free(tbuf);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;

    pkt->hw_type16 = constswap16(ARP_HW_ETHER);
    pkt->pro_type16 = constswap16(NET_PROTOCOL_IP);
    pkt->hw_len = NET_MAC_LEN;
    pkt->pro_len = NET_IP_LEN;
    pkt->opcode16 = constswap16(ARP_REPLY);
    memcpy(pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(pkt->sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - sizeof(arp_pkt_t));

    ethernet_out(buf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(arp_pkt_t))
        return;

    arp_pkt_t *hdr = (arp_pkt_t *)buf->data;
    uint16_t opcode = constswap16(hdr->opcode16);
    if (constswap16(hdr->hw_type16) != ARP_HW_ETHER ||
        constswap16(hdr->pro_type16) != NET_PROTOCOL_IP ||
        hdr->hw_len != NET_MAC_LEN ||
        hdr->pro_len != NET_IP_LEN ||
        (opcode != ARP_REQUEST && opcode != ARP_REPLY))
        return;

    uint8_t *src_ip = hdr->sender_ip;
    if (map_set(&arp_table, src_ip, src_mac) == -1)
        return;

    buf_t *cache = map_get(&arp_buf, src_ip);
    if (cache == NULL)
    {
        if (opcode == ARP_REQUEST && !memcmp(hdr->target_ip, net_if_ip, NET_IP_LEN))
            arp_resp(src_ip, src_mac);
    }
    else
    {
        ethernet_out(cache, src_mac, constswap16(hdr->pro_type16));
        map_delete(&arp_buf, src_ip);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    uint8_t *mac = map_get(&arp_table, ip);
    if (!memcmp(ip, net_if_ip, NET_IP_LEN))
        mac = net_if_mac;

    if (mac == NULL)
    {
        buf_t *cache = map_get(&arp_buf, ip);
        if (cache == NULL)
            arp_req(ip);
        map_set(&arp_buf, ip, buf);
    }
    else
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}