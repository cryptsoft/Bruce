/* SPDX-License-Identifier: Apache-2.0
 *
 * Tiny raw-API HTTP status endpoint -- proves the TCP path end-to-end from a
 * phone/laptop before the TLS management channel exists. Answers any GET
 * with a JSON status document and closes. Not a web server; three states
 * and no allocation beyond the TCP PCBs.
 */

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"
#include "pico/time.h"
#include "pico/unique_id.h"

#include "http_status.h"

static err_t http_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    (void) arg; (void) len;
    tcp_close(tpcb);
    return ERR_OK;
}

static err_t http_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    (void) arg;
    if (p == NULL) { /* peer closed */
        tcp_close(tpcb);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p); /* request content is irrelevant -- any request gets status */

    char id[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
    pico_get_unique_board_id_string(id, sizeof(id));

    char body[192];
    int blen = snprintf(body, sizeof(body),
                        "{\"device\":\"bruce-gadget\",\"fw\":\"0.1.0\","
                        "\"board_id\":\"%s\",\"uptime_ms\":%lu,"
                        "\"transport\":\"usb-ncm\",\"tls\":false}\n",
                        id, (unsigned long) to_ms_since_boot(get_absolute_time()));

    char rsp[320];
    int rlen = snprintf(rsp, sizeof(rsp),
                        "HTTP/1.0 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: close\r\n"
                        "\r\n%s",
                        blen, body);

    tcp_sent(tpcb, http_sent);
    if (tcp_write(tpcb, rsp, (u16_t) rlen, TCP_WRITE_FLAG_COPY) == ERR_OK) {
        tcp_output(tpcb);
    } else {
        tcp_close(tpcb);
    }
    return ERR_OK;
}

static err_t http_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void) arg;
    if (err != ERR_OK || newpcb == NULL) return ERR_VAL;
    tcp_recv(newpcb, http_recv);
    return ERR_OK;
}

void pqf_http_status_start(void)
{
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL) return;
    if (tcp_bind(pcb, IP_ANY_TYPE, 80) != ERR_OK) {
        tcp_abort(pcb);
        return;
    }
    pcb = tcp_listen_with_backlog(pcb, 2);
    if (pcb != NULL) tcp_accept(pcb, http_accept);
}
