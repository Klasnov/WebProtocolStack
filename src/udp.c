#include "udp.h"
#include "ip.h"
#include "icmp.h"
#include "utils.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 *
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @param protocol ip头部的协议号，由于执行udp_out时ip头部不存在，因此需手动传入
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // 添加UDP伪头部
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    // 拷贝伪头部
    udp_peso_hdr_t *peso_hdr = (udp_peso_hdr_t *)malloc(sizeof(udp_peso_hdr_t));
    memcpy(peso_hdr, buf->data, sizeof(udp_peso_hdr_t));
    // 填写伪头部信息
    udp_peso_hdr_t *p = (udp_peso_hdr_t *)buf->data;
    memcpy(p->src_ip, src_ip, NET_IP_LEN);
    memcpy(p->dst_ip, dst_ip, NET_IP_LEN);
    p->placeholder = 0;
    p->protocol = NET_PROTOCOL_UDP;
    p->total_len16 = hdr->total_len16;
    // 计算校验和
    uint16_t sum = checksum16((uint16_t *)buf->data, buf->len);
    // 复原UDP头部
    memcpy(buf->data, peso_hdr, sizeof(udp_peso_hdr_t));
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    // 返回校验和的值
    return sum;
}

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // 检查报头信息
    if (buf->len < sizeof(udp_hdr_t))
    {
        return;
    }
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    if (buf->len < swap16(hdr->total_len16))
    {
        return;
    }
    // 检查校验和
    if (udp_checksum(buf, src_ip, net_if_ip))
    {
        return;
    }
    // 检查端口号
    hdr->dst_port16 = swap16(hdr->dst_port16);
    udp_handler_t *handler = (udp_handler_t *)map_get(&udp_table, &hdr->dst_port16);
    if (handler)
    {
        // 如果找到回调函数，则交给回调函数处理
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(hdr->src_port16));
    }
    else
    {
        // 如果没有找到回调函数，ICMP不可达
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // 添加UDP报头
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    // 填充首部字段
    hdr->checksum16 = 0;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);
    hdr->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    // 发送数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}