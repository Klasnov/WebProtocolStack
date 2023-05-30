#include <assert.h>
#include "map.h"
#include "tcp.h"
#include "ip.h"

#define MAX_SQE_RND 100

static void panic(const char *msg, int line)
{
    printf("panic %s! at line %d\n", msg, line);
    assert(0);
}

static void display_flags(tcp_flags_t flags)
{
    printf("flags:%s%s%s%s%s%s%s%s\n",
           flags.cwr ? " cwr" : "",
           flags.ece ? " ece" : "",
           flags.urg ? " urg" : "",
           flags.ack ? " ack" : "",
           flags.psh ? " psh" : "",
           flags.rst ? " rst" : "",
           flags.syn ? " syn" : "",
           flags.fin ? " fin" : "");
}

// dst-port -> handler
static map_t tcp_table; // tcp_table里面放了一个dst_port的回调函数

// tcp_key_t[IP, src port, dst port] -> tcp_connect_t

/* Connect_table放置了一堆TCP连接，
    KEY为[IP，src port，dst port], 即tcp_key_t，VALUE为tcp_connect_t。
*/
static map_t connect_table;

/**
 * @brief 生成一个用于 connect_table 的 key
 *
 * @param ip
 * @param src_port
 * @param dst_port
 * @return tcp_key_t
 */
static tcp_key_t new_tcp_key(uint8_t ip[NET_IP_LEN], uint16_t src_port, uint16_t dst_port)
{
    tcp_key_t key;
    memcpy(key.ip, ip, NET_IP_LEN);
    key.src_port = src_port;
    key.dst_port = dst_port;
    return key;
}

/**
 * @brief 初始化tcp在静态区的map
 *        供应用层使用
 *
 */
void tcp_init()
{
    map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
    map_init(&connect_table, sizeof(tcp_key_t), sizeof(tcp_connect_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
}

/**
 * @brief 向 port 注册一个 TCP 连接以及关联的回调函数
 *        供应用层使用
 *
 * @param port
 * @param handler
 * @return int
 */
int tcp_open(uint16_t port, tcp_handler_t handler)
{
    printf("tcp open\n");
    return map_set(&tcp_table, &port, &handler);
}

/**
 * @brief 完成了缓存分配工作，状态也会切换为TCP_SYN_RCVD
 *        rx_buf和tx_buf在触及边界时会把数据重新移动到头部，防止溢出。
 *
 * @param connect
 */
static void init_tcp_connect_rcvd(tcp_connect_t *connect)
{
    if (connect->state == TCP_LISTEN)
    {
        connect->rx_buf = malloc(sizeof(buf_t));
        connect->tx_buf = malloc(sizeof(buf_t));
    }
    buf_init(connect->rx_buf, 0);
    buf_init(connect->tx_buf, 0);
    connect->state = TCP_SYN_RCVD;
}

/**
 * @brief 释放TCP连接，这会释放分配的空间，并把状态变回LISTEN。
 *        一般这个后边都会跟个map_delete(&connect_table, &key)把状态变回CLOSED
 *
 * @param connect
 */
static void release_tcp_connect(tcp_connect_t *connect)
{
    if (connect->state == TCP_LISTEN)
        return;
    free(connect->rx_buf);
    free(connect->tx_buf);
    connect->state = TCP_LISTEN;
}

static uint16_t tcp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    uint16_t len = (uint16_t)buf->len;
    tcp_peso_hdr_t *peso_hdr = (tcp_peso_hdr_t *)(buf->data - sizeof(tcp_peso_hdr_t));
    tcp_peso_hdr_t pre; // 暂存被覆盖的IP头
    memcpy(&pre, peso_hdr, sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->placeholder = 0;
    peso_hdr->protocol = NET_PROTOCOL_TCP;
    peso_hdr->total_len16 = swap16(len);
    uint16_t checksum = checksum16((uint16_t *)peso_hdr, len + sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr, &pre, sizeof(tcp_peso_hdr_t));
    return checksum;
}

static _Thread_local uint16_t delete_port;

/**
 * @brief tcp_close使用这个函数来查找可以关闭的连接，使用thread-local变量delete_port传递端口号。
 *
 * @param key,value,timestamp
 */
static void close_port_fn(void *key, void *value, time_t *timestamp)
{
    tcp_key_t *tcp_key = key;
    tcp_connect_t *connect = value;
    if (tcp_key->dst_port == delete_port)
    {
        release_tcp_connect(connect);
    }
}

/**
 * @brief 关闭 port 上的 TCP 连接
 *        供应用层使用
 *
 * @param port
 */
void tcp_close(uint16_t port)
{
    delete_port = port;
    map_foreach(&connect_table, close_port_fn);
    map_delete(&tcp_table, &port);
}

/**
 * @brief 从 buf 中读取数据到 connect->rx_buf
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_read_from_buf(tcp_connect_t *connect, buf_t *buf)
{
    uint8_t *dst = connect->rx_buf->data + connect->rx_buf->len;
    buf_add_padding(connect->rx_buf, buf->len);
    memcpy(dst, buf->data, buf->len);
    connect->ack += buf->len;
    return buf->len;
}

/**
 * @brief 把connect内tx_buf的数据写入到buf里面供tcp_send使用，buf原来的内容会无效。
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_write_to_buf(tcp_connect_t *connect, buf_t *buf)
{
    uint16_t sent = connect->next_seq - connect->unack_seq;
    uint16_t size = min32(connect->tx_buf->len - sent, connect->remote_win);
    buf_init(buf, size);
    memcpy(buf->data, connect->tx_buf->data + sent, size);
    connect->next_seq += size;
    return size;
}

/**
 * @brief 发送TCP包, seq_number32 = connect->next_seq - buf->len
 *        buf里的数据将作为负载，加上tcp头发送出去。如果flags包含syn或fin，seq会递增。
 *
 * @param buf
 * @param connect
 * @param flags
 */
static void tcp_send(buf_t *buf, tcp_connect_t *connect, tcp_flags_t flags)
{
    // printf("<< tcp send >> sz=%zu\n", buf->len);
    display_flags(flags);
    size_t prev_len = buf->len;
    buf_add_header(buf, sizeof(tcp_hdr_t));
    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(connect->local_port);
    hdr->dst_port16 = swap16(connect->remote_port);
    hdr->seq_number32 = swap32(connect->next_seq - prev_len);
    hdr->ack_number32 = swap32(connect->ack);
    hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
    hdr->reserved = 0;
    hdr->flags = flags;
    hdr->window_size16 = swap16(connect->remote_win);
    hdr->chunksum16 = 0;
    hdr->urgent_pointer16 = 0;
    hdr->chunksum16 = tcp_checksum(buf, connect->ip, net_if_ip);
    ip_out(buf, connect->ip, NET_PROTOCOL_TCP);
    if (flags.syn || flags.fin)
    {
        connect->next_seq += 1;
    }
}

/**
 * @brief 从外部关闭一个TCP连接, 会发送剩余数据
 *        供应用层使用
 *
 * @param connect
 */
void tcp_connect_close(tcp_connect_t *connect)
{
    if (connect->state == TCP_ESTABLISHED)
    {
        tcp_write_to_buf(connect, &txbuf);
        tcp_send(&txbuf, connect, tcp_flags_ack_fin);
        connect->state = TCP_FIN_WAIT_1;
        return;
    }
    tcp_key_t key = new_tcp_key(connect->ip, connect->remote_port, connect->local_port);
    release_tcp_connect(connect);
    map_delete(&connect_table, &key);
}

/**
 * @brief 从 connect 中读取数据到 buf，返回成功的字节数。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 * @return size_t
 */
size_t tcp_connect_read(tcp_connect_t *connect, uint8_t *data, size_t len)
{
    buf_t *rx_buf = connect->rx_buf;
    size_t size = min32(rx_buf->len, len);
    memcpy(data, rx_buf->data, size);
    if (buf_remove_header(rx_buf, size) != 0)
    {
        memmove(rx_buf->payload, rx_buf->data, rx_buf->len);
        rx_buf->data = rx_buf->payload;
    }
    return size;
}

/**
 * @brief 往connect的tx_buf里面写东西，返回成功的字节数，这里要判断窗口够不够，否则图片显示不全。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 */
size_t tcp_connect_write(tcp_connect_t *connect, const uint8_t *data, size_t len)
{
    // printf("tcp_connect_write size: %zu\n", len);
    buf_t *tx_buf = connect->tx_buf;

    uint8_t *dst = tx_buf->data + tx_buf->len;
    size_t size = min32(&tx_buf->payload[BUF_MAX_LEN] - dst, len);

    if (connect->next_seq - connect->unack_seq + len >= connect->remote_win)
    {
        return 0;
    }
    if (buf_add_padding(tx_buf, size) != 0)
    {
        memmove(tx_buf->payload, tx_buf->data, tx_buf->len);
        tx_buf->data = tx_buf->payload;
        if (tcp_write_to_buf(connect, &txbuf))
        {
            tcp_send(&txbuf, connect, tcp_flags_ack);
        }
        return 0;
    }
    memcpy(dst, data, size);
    return size;
}

/**
 * @brief 服务器端TCP收包
 *
 * @param buf
 * @param src_ip
 */
void tcp_in(buf_t *buf, uint8_t *src_ip)
{
    // 大小检查，检查buf长度是否小于tcp头部，如果是，则丢弃
    if (buf->len < sizeof(tcp_hdr_t))
    {
        return;
    }

    // 检查checksum字段，如果checksum出错，则丢弃
    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
    uint16_t chk = hdr->chunksum16;
    hdr->chunksum16 = 0;
    uint16_t rlt = tcp_checksum(buf, src_ip, net_if_ip);
    if (rlt == chk)
    {
        hdr->chunksum16 = chk;
    }
    else
    {
        return;
    }

    // 从tcp头部字段中获取必要数据
    uint16_t srcPort = swap16(hdr->src_port16);
    uint16_t dstPort = swap16(hdr->dst_port16);
    uint32_t getSeq = swap32(hdr->seq_number32);
    uint32_t getAck = swap32(hdr->ack_number32);
    tcp_flags_t flags = hdr->flags;

    // 调用map_get函数，根据destination port查找对应的handler函数
    tcp_handler_t *handler = (tcp_handler_t *)map_get(&tcp_table, &dstPort);
    if (!handler)
    {
        return;
    }

    // 根据通信五元组中的源IP地址、目标IP地址、目标端口号确定一个tcp链接key
    tcp_key_t key = new_tcp_key(src_ip, srcPort, dstPort);

    // 调用map_get函数，根据key查找一个tcp_connect_t* connect，
    tcp_connect_t *connect = map_get(&connect_table, &key);
    if (!connect)
    {
        map_set(&connect_table, &key, &CONNECT_LISTEN);
        connect = map_get(&connect_table, &key);
    }

    // 从TCP头部字段中获取对方的窗口大小，注意大小端转换
    uint16_t windowSize = swap16(hdr->window_size16);

    // TCP_LISTEN状态
    if (connect->state == TCP_LISTEN)
    {
        if (flags.rst)
        {
            // 收到的flag带有rst
            release_tcp_connect(connect);
            map_delete(&connect_table, &key);
            return;
        }
        if (!flags.syn)
        {
            // 收到的flag不是syn
            connect->next_seq = 0;
            connect->ack = getSeq + 1;
            buf_init(&txbuf, 0);
            tcp_send(&txbuf, connect, tcp_flags_ack_rst);
        }
        // 初始化connect并填充connect字段
        init_tcp_connect_rcvd(connect);
        connect->local_port = dstPort;
        connect->remote_port = srcPort;
        memcpy(connect->ip, src_ip, NET_IP_LEN);
        srand(time(NULL));
        uint32_t rnd = rand() % MAX_SQE_RND;
        connect->unack_seq = rnd;
        connect->next_seq = rnd;
        connect->ack = getSeq + 1;
        connect->remote_win = windowSize;
        // 处理发送信息
        buf_init(&txbuf, 0);
        tcp_send(&txbuf, connect, tcp_flags_ack_syn);
        return;
    }

    // 检查接收到的sequence number
    if (getSeq != connect->ack)
    {
        connect->next_seq = 0;
        connect->ack = getSeq + 1;
        buf_init(&txbuf, 0);
        tcp_send(&txbuf, connect, tcp_flags_ack_rst);
    }

    // 检查flags的rst标志
    if (flags.rst)
    {
        release_tcp_connect(connect);
        map_delete(&connect_table, &key);
        return;
    }

    // 相同序号处理
    buf_remove_header(buf, sizeof(tcp_hdr_t));
    switch (connect->state)
    {
    case TCP_LISTEN:
        panic("switch TCP_LISTEN", __LINE__);
        break;

    case TCP_SYN_RCVD:

        // 收到的包没有ack flag
        if (!flags.ack)
        {
            break;
        }

        // 收到ack包，需要完成如下功能：
        connect->unack_seq++;
        connect->state = TCP_ESTABLISHED;
        (*handler)(connect, TCP_CONN_CONNECTED);
        break;

    case TCP_ESTABLISHED:

        // 收到的包没有ack且没有fin
        if (!flags.ack && !flags.fin)
        {
            break;
        }

        // 处理ACK的值
        if (flags.ack &&
            connect->unack_seq < getAck &&
            connect->next_seq >= getAck)
        {
            buf_remove_header(connect->tx_buf, min32(getAck - connect->unack_seq, connect->next_seq - connect->unack_seq));
            connect->unack_seq = min32(getAck, connect->next_seq);
        }

        // 调用tcp_read_from_buf函数，把buf放入rx_buf中
        tcp_read_from_buf(connect, buf);

        // 根据当前的标志位进一步处理
        buf_init(&txbuf, 0);
        if (flags.fin)
        {
            connect->state = TCP_LAST_ACK;
            connect->ack++;
            tcp_send(&txbuf, connect, tcp_flags_ack_fin);
            break;
        }
        if (buf->len > 0)
        {
            (*handler)(connect, TCP_CONN_DATA_RECV);
            tcp_write_to_buf(connect, &txbuf);
            tcp_send(&txbuf, connect, tcp_flags_ack);
        }
        break;

    case TCP_CLOSE_WAIT:
        panic("switch TCP_CLOSE_WAIT", __LINE__);
        break;

    case TCP_FIN_WAIT_1:

        // 收到FIN && ACK以及只收到ACK
        if (flags.fin && flags.ack)
        {
            release_tcp_connect(connect);
            map_delete(&connect_table, &key);
            return;
        }
        if (flags.ack)
        {
            connect->state = TCP_FIN_WAIT_2;
        }
        break;

    case TCP_FIN_WAIT_2:
        // 如果是FIN
        if (flags.fin)
        {
            connect->ack++;
            buf_init(&txbuf, 0);
            tcp_send(&txbuf, connect, tcp_flags_ack);
            release_tcp_connect(connect);
            map_delete(&connect_table, &key);
            return;
        }
        break;

    case TCP_LAST_ACK:
        if (flags.ack)
        {
            (*handler)(connect, TCP_CONN_CLOSED);
            release_tcp_connect(connect);
            map_delete(&connect_table, &key);
            return;
        }

    default:
        panic("connect->state", __LINE__);
        break;
    }
    return;
}
