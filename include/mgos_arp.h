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

#pragma once

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mgos_arp_scan_result {
    ip4_addr_t ip_addr;
    struct eth_addr eth_addr;
};

typedef void (*mgos_arp_scan_cb_t)(int num_res,
                                    struct mgos_arp_scan_result *res,
                                    void *arg);

void mgos_arp_scan(mgos_arp_scan_cb_t cb, void *arg);

// library
bool mgos_arp_init(void);

#ifdef __cplusplus
}
#endif
