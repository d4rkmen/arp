/*
 * Copyright 2020 d4rkmen <darkmen@i.ua>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mgos.h"
#include "mgos_rpc.h"
#include "netif/etharp.h"
#include "mgos_arp.h"

static int s_hoststart = 1;
static int s_hostend = 255;
static u32_t s_network = 0;

struct cb_info {
    mgos_arp_scan_cb_t cb; // user callback
    void* arg;             // user arg
};

int mgos_arp_request(struct netif* netif, const ip4_addr_t* ipaddr) {
    struct pbuf* p;
    err_t result = ERR_OK;
    struct etharp_hdr* hdr;

    assert(netif != NULL);

    p = pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR, PBUF_RAM);
    if (p == NULL) {
        LOG(LL_ERROR, ("could not allocate pbuf for ARP request"));
        return ERR_MEM;
    }
    assert(p->len >= SIZEOF_ETHARP_HDR);

    hdr = (struct etharp_hdr*) p->payload;
    LOG(LL_DEBUG, ("sending raw ARP packet"));
    hdr->opcode = lwip_htons(ARP_REQUEST);
    assert(netif->hwaddr_len == ETH_HWADDR_LEN);

    /* Write the ARP MAC-Addresses */
    memcpy(&hdr->shwaddr, netif->hwaddr, ETH_HWADDR_LEN);
    memcpy(&hdr->dhwaddr, &ethzero, ETH_HWADDR_LEN);
    /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
     * structure packing. */
    memcpy(&hdr->sipaddr, netif_ip4_addr(netif), sizeof(ip4_addr_t));
    memcpy(&hdr->dipaddr, ipaddr, sizeof(ip4_addr_t));

    hdr->hwtype = PP_HTONS(1); //LWIP_IANA_HWTYPE_ETHERNET
    hdr->proto = PP_HTONS(ETHTYPE_IP);
    /* set hwlen and protolen */
    hdr->hwlen = ETH_HWADDR_LEN;
    hdr->protolen = sizeof(ip4_addr_t);

    /* send ARP query */
    ethernet_output(netif, p, (struct eth_addr*) netif->hwaddr, &ethbroadcast, ETHTYPE_ARP);
    /* free ARP query packet */
    pbuf_free(p);
    p = NULL;
    /* could not allocate pbuf for ARP request */

    return result;
}

static void swap(struct mgos_arp_scan_result* a, struct mgos_arp_scan_result* b) {
    struct mgos_arp_scan_result tmp;
    tmp = *a;
    *a = *b;
    *b = tmp;
    (void) a;
    (void) b;
}

static int arp_scan_result_printer(struct json_out* out, va_list* ap) {
    int len = 0;
    int num_res = va_arg(*ap, int);

    struct mgos_arp_scan_result* r = va_arg(*ap, struct mgos_arp_scan_result*);
    // Sorting by ip
    for (int i = 0; i < num_res; i++)
        for (int j = 1; j < num_res - i; j++)
            if (ntohl(r[j].ip_addr.addr) < ntohl(r[j - 1].ip_addr.addr))
                swap(&r[j], &r[j - 1]);

    for (int i = 0; i < num_res; i++) {
        if (i)
            len += json_printf(out, ", ");

        len += json_printf(
                out,
                "{ip: \"%u.%u.%u.%u\", mac: \"%02x:%02x:%02x:%02x:%02x:%02x\"}",
                ip4_addr1_16(&r->ip_addr),
                ip4_addr2_16(&r->ip_addr),
                ip4_addr3_16(&r->ip_addr),
                ip4_addr4_16(&r->ip_addr),
                (u16_t) r->eth_addr.addr[0],
                (u16_t) r->eth_addr.addr[1],
                (u16_t) r->eth_addr.addr[2],
                (u16_t) r->eth_addr.addr[3],
                (u16_t) r->eth_addr.addr[4],
                (u16_t) r->eth_addr.addr[5]);
        r++;
    }

    return len;
}

static void arp_scan_rpc_cb(int n, struct mgos_arp_scan_result* res, void* arg) {
    struct mg_rpc_request_info* ri = (struct mg_rpc_request_info*) arg;
    if (n < 0) {
        mg_rpc_send_errorf(ri, n, "ARP scan failed");
        return;
    }
    mg_rpc_send_responsef(ri, "[%M]", arp_scan_result_printer, n, res);
}

static void scan_done_cb(mgos_arp_scan_cb_t cb, void* arg) {
    // Sending out ARP table
    struct mgos_arp_scan_result* res = calloc(ARP_TABLE_SIZE, sizeof(struct mgos_arp_scan_result));
    int n = 0;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t* ip;
        struct netif* nif;
        struct eth_addr* ethaddr;
        int r = etharp_get_entry(i, &ip, &nif, &ethaddr);
        if (r) {
            LOG(LL_DEBUG,
                ("%d.%d.%d.%d %02X:%02X:%02X:%02X:%02X:%02X",
                 ip4_addr1_16(ip),
                 ip4_addr2_16(ip),
                 ip4_addr3_16(ip),
                 ip4_addr4_16(ip),
                 (u16_t) ethaddr->addr[0],
                 (u16_t) ethaddr->addr[1],
                 (u16_t) ethaddr->addr[2],
                 (u16_t) ethaddr->addr[3],
                 (u16_t) ethaddr->addr[4],
                 (u16_t) ethaddr->addr[5]));
            memcpy(&res[n].ip_addr, ip, sizeof(ip4_addr_t));
            memcpy(&res[n].eth_addr, ethaddr, sizeof(struct eth_addr));
            n++;
        }
    }
    LOG(LL_DEBUG, ("Total: %d items", n));
    cb(n, res, arg);
    free(res);
}

static void arp_scan_request(void* arg) {
    ip4_addr_t ip;
    ip.addr = htonl(s_network + s_hoststart);
    LOG(LL_INFO, ("    %u.%u.%u.%u", ip4_addr1_16(&ip), ip4_addr2_16(&ip), ip4_addr3_16(&ip), ip4_addr4_16(&ip)));
    // err_t err = etharp_request(netif_default, &ip);
    err_t err = mgos_arp_request(netif_default, &ip);
    if (err)
        LOG(LL_ERROR,
            ("Request for %u.%u.%u.%u failed (code %ld)",
             ip4_addr1_16(&ip),
             ip4_addr2_16(&ip),
             ip4_addr3_16(&ip),
             ip4_addr4_16(&ip),
             (long) err));
    s_hoststart++;

    if (s_hoststart < s_hostend)
        mgos_set_timer(5, 0, arp_scan_request, arg);
    else {
        s_network = 0;
        LOG(LL_INFO, ("ARP scanning done"));
        struct cb_info* ci = (struct cb_info*) arg;
        scan_done_cb(ci->cb, ci->arg);
        free(ci);
    }
}

void mgos_arp_scan(mgos_arp_scan_cb_t cb, void* arg) {
    if (s_network) {
        LOG(LL_WARN, ("ARP scanning still pending"));
        // Sending out current results
        scan_done_cb(cb, arg);
        return;
    }
    LOG(LL_DEBUG, ("Scanning APR..."));

    ip4_addr_t network, netmask;
    ip4_addr_set(&network, ip_2_ip4(&netif_default->ip_addr));
    ip4_addr_set(&netmask, ip_2_ip4(&netif_default->netmask));
    // Calculating humber of hosts by netmask
    int bits = 0;
    u32_t net = ntohl(network.addr);  // host byte order
    u32_t mask = ntohl(netmask.addr); // host byte order
    for (int i = 0; i < 32; i++)
        if (mask & (1 << i))
            bits++;
    if (bits < 3 || bits > 32) {
        LOG(LL_ERROR, ("Netmask bits must be between 3 and 32"));
        return;
    }
    s_network = net & mask;

    s_hoststart = 1;
    s_hostend = (1 << (32 - bits)) - 1;
    ip4_addr_t ip;
    ip.addr = htonl(s_network);
    LOG(LL_INFO,
        ("Polling %u.%u.%u.%u/%lu (%ld hosts)",
         ip4_addr1_16(&ip),
         ip4_addr2_16(&ip),
         ip4_addr3_16(&ip),
         ip4_addr4_16(&ip),
         (long) bits,
         (long) (s_hostend - s_hoststart)));
    struct cb_info* ci = malloc(sizeof(struct cb_info));
    ci->cb = cb;
    ci->arg = arg;
    arp_scan_request((void*) ci);
}

static void
        scan_handler(struct mg_rpc_request_info* ri, void* cb_arg, struct mg_rpc_frame_info* fi, struct mg_str args) {
    mgos_arp_scan(arp_scan_rpc_cb, ri);
    (void) args;
    (void) cb_arg;
    (void) fi;
}

bool mgos_arp_init(void) {
    if (mgos_sys_config_get_arp_rpc_enable()) {
        struct mg_rpc* c = mgos_rpc_get_global();
        mg_rpc_add_handler(c, "ARP.Scan", "{}", scan_handler, NULL);
    }
    return true;
}
