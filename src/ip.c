#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include <string.h>

uint16_t ip_id = 0;

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(ip_hdr_t))
    {
        // 数据包长度小于IP头部长度，丢弃不处理
        return;
    }
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    if (hdr->version != IP_VERSION_4 || swap16(hdr->total_len16) > buf->len)
    {
        // IP头部的版本号不是IPv4或总长度字段大于接收到的包的长度，丢弃不处理
        return;
    }
    if (memcmp(net_if_ip, hdr->dst_ip, NET_IP_LEN))
    {
        // 目的IP地址不是本机的IP地址，丢弃不处理
        return;
    }
    // 头部校验和不匹配，丢弃不处理
    ip_hdr_t *chk = (ip_hdr_t *)malloc(sizeof(ip_hdr_t));
    memcpy(chk, buf->data, sizeof(ip_hdr_t));
    chk->hdr_checksum16 = 0;
    uint16_t rlt = checksum16((uint16_t *)chk, sizeof(ip_hdr_t));
    if (rlt != hdr->hdr_checksum16)
    {
        return;
    }
    free(chk);

    // 如果接收到的数据包的长度大于IP头部的总长度字段，则去除填充字段
    buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    // 去掉IP报头
    ip_hdr_t *tmp = (ip_hdr_t *)malloc(sizeof(ip_hdr_t));
    memcpy(tmp, hdr, sizeof(ip_hdr_t));
    buf_remove_header(buf, sizeof(ip_hdr_t));
    // 调用net_in()函数向上层传递数据包
    if (net_in(buf, hdr->protocol, hdr->src_ip) == -1)
    {
        // 不能识别的协议类型，返回ICMP协议不可达信息
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    free(tmp);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 增加IP数据报头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_header = (ip_hdr_t *)buf->data;

    // 填写IP数据报头部字段
    ip_header->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE; // IP头部长度，单位为4字节
    ip_header->version = IP_VERSION_4;                           // IP版本号
    ip_header->tos = 0;                                          // 服务类型，可根据需求设置
    ip_header->total_len16 = swap16(buf->len);                   // 总长度，包括IP头部和数据部分的长度
    ip_header->id16 = swap16(id);                                // 数据包标识符
    uint16_t flags_fragment = (mf << 13) | offset;
    ip_header->flags_fragment16 = swap16(flags_fragment); // 分段偏移
    ip_header->ttl = IP_DEFALUT_TTL;                      // 存活时间，可根据需求设置
    ip_header->protocol = protocol;                       // 上层协议类型
    ip_header->hdr_checksum16 = 0;                        // 首部校验和先置0
    memcpy(ip_header->src_ip, net_if_ip, NET_IP_LEN);     // 源IP地址
    memcpy(ip_header->dst_ip, ip, NET_IP_LEN);            // 目标IP地址

    // 计算首部校验和
    ip_header->hdr_checksum16 = checksum16((uint16_t *)ip_header, sizeof(ip_hdr_t));

    // 调用arp_out函数将封装后的IP头部和数据发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    uint16_t offset = 0;
    size_t len = buf->len;
    buf_t *tbuf = (buf_t *)malloc(sizeof(buf_t));

    while (len - offset * IP_HDR_OFFSET_PER_BYTE > ETHERNET_MAX_TRANSPORT_UNIT)
    {
        // 超过IP协议最大负载包长，需要分片发送
        size_t l = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
        buf_init(tbuf, l);
        memcpy(tbuf->data, buf->data + offset * IP_HDR_OFFSET_PER_BYTE, l);
        // 发送分片
        ip_fragment_out(tbuf, ip, protocol, ip_id, offset, 1);
        offset += (ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)) / IP_HDR_OFFSET_PER_BYTE;
    }

    size_t l = len - offset * IP_HDR_OFFSET_PER_BYTE;
    buf_init(tbuf, l);
    memcpy(tbuf->data, buf->data + offset * IP_HDR_OFFSET_PER_BYTE, l);
    ip_fragment_out(tbuf, ip, protocol, ip_id++, offset, 0);

    free(tbuf);
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}