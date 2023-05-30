#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"

/**
 * @brief 比较目的mac地址是否与本机mac地址相同（或为广播地址）
 * 
 * @param dst 目的mac地址
 * @return int 相同（或为广播地址）为1，否则为0
*/
int is_mac_equal(uint8_t *dst){
    if (!memcmp(dst, net_if_mac, NET_MAC_LEN) || !memcmp(dst, ether_broadcast_mac, NET_MAC_LEN))
        return 1;
    return 0;
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    if (buf->len < sizeof(ether_hdr_t))
        return ;
    
    ether_hdr_t *hdr = (ether_hdr_t*)buf->data;
    buf_remove_header(buf, sizeof(ether_hdr_t));

    if (is_mac_equal(hdr->dst)){
        if (net_in(buf, swap16(hdr->protocol16), hdr->src) == -1)
            fprintf(stderr, "ethernet_in failed");
    }

}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT)
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);

    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t*)buf->data;

    memcpy(hdr->dst, mac, NET_MAC_LEN);
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);

    if (driver_send(buf) == -1)
        fprintf(stderr, "ethernet_out failed\n");
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
