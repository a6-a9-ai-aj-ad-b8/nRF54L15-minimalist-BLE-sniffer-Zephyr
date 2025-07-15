# BLE Sniffer for nRF54L15

This project implements a simple Bluetooth Low Energy (BLE) advertising packet sniffer on the Nordic nRF54L15-DK, based on Zephyr RTOS.

## Features
- Passive scanning of nearby BLE devices
- optimised intervals to catch every packet in area
- Logs UUID (16-bit and 128-bit)
- Logs manufacturer data with human-readable labels
- Uses Zephyr Bluetooth stack
- Designed for low power and small memory footprint

## Hardware
- Tested on Nordic nRF54L15-DK

## How to build
```bash
west build -b nrf54l15dk_nrf54l15 -p
