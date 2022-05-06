#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    icmp_hdr_t *hdr_resp = (icmp_hdr_t *)txbuf.data;
    icmp_hdr_t *hdr_req  = (icmp_hdr_t *)req_buf->data;

    hdr_resp->type       = ICMP_TYPE_ECHO_REPLY;
    hdr_resp->code       = 0;
    hdr_resp->id16       = hdr_req->id16;
    hdr_resp->seq16      = hdr_req->seq16;

    hdr_resp->checksum16 = 0;
    hdr_resp->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    if (buf->len < 8)
        return;

    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;

    uint16_t check_sum16 = hdr->checksum16;
    hdr->checksum16 = 0;
    if (check_sum16 ^ checksum16((uint16_t *)buf->data, buf->len))
        return;
    hdr->checksum16 = check_sum16;

    if (hdr->type == ICMP_TYPE_ECHO_REQUEST && hdr->code == 0)
        icmp_resp(buf, src_ip);
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
    // TO-DO
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;

    hdr->type       = ICMP_TYPE_UNREACH;
    hdr->code       = code;
    hdr->id16       = swap16(0);                    // 未用，必须 0
    hdr->seq16      = swap16(0);                    // 未用，必须 0

    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}