#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief ping请求的回调函数map<id&seq, func>
 */
extern map_t icmp_req_map;

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    icmp_hdr_t *hdr = (icmp_hdr_t *)req_buf->data;
    // 封装数据与填写校验和
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)req_buf->data, req_buf->len);
    // 发送数据报
    ip_out(req_buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 发送icmp请求
 *
 * @param id 标识号
 * @param seq 序列号
 * @param tag 时间戳
 * @param dst_ip 目的ip地址
 */
void icmp_req(uint16_t id, uint16_t seq, clock_t tag, uint8_t *dst_ip)
{
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(icmp_hdr_t));
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    hdr->type = ICMP_TYPE_ECHO_REQUEST;
    hdr->code = 0;
    hdr->id16 = swap16(id);
    hdr->seq16 = swap16(seq);
    hdr->checksum16 = 0;

    buf_add_padding(buf, 32);
    memcpy(buf->data + sizeof(icmp_hdr_t), &tag, sizeof(clock_t));
    hdr->checksum16 = checksum16((uint16_t *)buf->data, buf->len);

    ip_out(buf, dst_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(icmp_hdr_t))
    {
        // 接收到的包长度小于ICMP头部长度，丢弃不处理
        return;
    }

    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST)
    {
        // 是回显请求，回送回显应答
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{  
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);

    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum16 = 0;
    icmp_hdr->id16 = 0;
    icmp_hdr->seq16 = 0;

    // 填写ICMP数据部分，包括IP数据报首部和IP数据报的前8个字节的数据字段
    ip_hdr_t *ip_hdr = (ip_hdr_t *)(buf->data + sizeof(icmp_hdr_t));
    memcpy(ip_hdr, recv_buf->data, sizeof(ip_hdr_t) + 8);

    // 填写校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)icmp_hdr, buf->len);

    ip_out(buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init()
{
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}