#ifndef BT_SNIFFER_H
#define BT_SNIFFER_H

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <stdio.h>
#include <zephyr/sys/poweroff.h>

void device_found(const bt_addr_le_t *addr, int8_t current_rssi, uint8_t type, struct net_buf_simple *ad);// necessary function for scan
void scan(int interval, int window, int length_ms);
#endif
