#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

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
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *data = (arp_pkt_t *)txbuf.data;  // 下层自动 padding
    
    *data = arp_init_pkt;   // 可用等号赋值结构体

    data->opcode16 = swap16(ARP_REQUEST);
    memcpy(data->target_ip, target_ip, NET_IP_LEN);

    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *data = (arp_pkt_t *)txbuf.data;
    
    *data = arp_init_pkt;

    data->opcode16 = swap16(ARP_REPLY);
    memcpy(data->target_ip, target_ip, NET_IP_LEN);
    memcpy(data->target_mac, target_mac, NET_MAC_LEN);

    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if (buf->len < 8) {
        return;
    }

    arp_pkt_t *data = (arp_pkt_t *)buf->data;
    if (data->hw_type16  !=  arp_init_pkt.hw_type16  ||
        data->pro_type16 !=  arp_init_pkt.pro_type16 ||
        data->hw_len     !=  arp_init_pkt.hw_len     ||
        data->pro_len    !=  arp_init_pkt.pro_len    ||
        (data->opcode16  !=  swap16(ARP_REQUEST)     && data->opcode16 != swap16(ARP_REPLY))) {
        // ？
        return;
    }

    // src_mac 和 arp->sender_mac 一样
    map_set(&arp_table, data->sender_ip, src_mac);

    buf_t *bf;
    if ((bf = map_get(&arp_buf, data->sender_ip))) {
        ethernet_out(bf, src_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, data->sender_ip);

    } else if (data->opcode16 == swap16(ARP_REQUEST) && memcmp(data->target_ip, net_if_ip, NET_IP_LEN) == 0) {
        arp_resp(data->sender_ip, src_mac);
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
    // TO-DO
    uint8_t *mac;
    if ((mac = map_get(&arp_table, ip))) {
        ethernet_out(buf, mac, NET_PROTOCOL_IP);

    } else if (!map_get(&arp_buf, ip)) {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
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