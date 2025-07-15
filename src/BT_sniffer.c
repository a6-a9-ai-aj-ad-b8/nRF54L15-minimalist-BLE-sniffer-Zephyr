/***********************************************************************************************/
/*::##::: ##:'########::'########:'########:'##::::::::::::BT_sniffer.c::::::::::::::::::::::::*/
/*::###:: ##: ##.... ##: ##.....:: ##.....:: ##:::'##::::::::::::::::::::::::::::::::::::::::::*/
/*::####: ##: ##:::: ##: ##::::::: ##::::::: ##::: ##::::::Author: a6a9aia:::::::::::::::::::::*/
/*::## ## ##: ########:: ######::: #######:: ##::: ##::::::<a5a8ahaiac@proton.me>::::::::::::::*/
/*::##. ####: ##.. ##::: ##...::::...... ##: #########:::::::::::::::::::::::::::::::::::::::::*/
/*::##:. ###: ##::. ##:: ##:::::::'##::: ##:...... ##::::::Created: 2025/07/14 by a6a9aia::::::*/
/*::##::. ##: ##:::. ##: ##:::::::. ######:::::::: ##::::::Updated: 2025/07/15 by a6a9aia::::::*/
/*::..::::..::..:::::..::..:::::::::......:::::::::..::::::::::::::::::::::::::::::::::::::::::*/
/***********************************************************************************************/
/*::########::'########:::::'######::'##::: ##:'####:'########:'########:'########:'########:::*/
/*::##.... ##:... ##..:::::'##... ##: ###:: ##:. ##:: ##.....:: ##.....:: ##.....:: ##.... ##::*/
/*::##:::: ##:::: ##::::::: ##:::..:: ####: ##:: ##:: ##::::::: ##::::::: ##::::::: ##:::: ##::*/
/*::########::::: ##:::::::. ######:: ## ## ##:: ##:: ######::: ######::: ######::: ########:::*/
/*::##.... ##:::: ##::::::::..... ##: ##. ####:: ##:: ##...:::: ##...:::: ##...:::: ##.. ##::::*/
/*::##:::: ##:::: ##:::::::'##::: ##: ##:. ###:: ##:: ##::::::: ##::::::: ##::::::: ##::. ##:::*/
/*::########::::: ##:::::::. ######:: ##::. ##:'####: ##::::::: ##::::::: ########: ##:::. ##::*/
/*::........::::::..:::::::::......:::..::::..::....::..::::::::..::::::::........::..:::::..::*/
/***********************************************************************************************/

#include "BT_sniffer.h"
LOG_MODULE_REGISTER(detector, LOG_LEVEL_INF);

#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME)-1)

typedef struct {
    uint16_t uuid;
    const char* description;
} uuid16_desc_t;

//     ===== TABLE UUIDs =====
static const uuid16_desc_t uuid16_table[] = {
    { 0x1800, "Generic Access" },
    { 0x1801, "Generic Attribute" },
    { 0x180A, "Device Information" },
    { 0x180F, "Battery Service" },
    { 0x181A, "Environmental Sensing" },
    { 0xFE2C, "Tile Inc. (Proximity Service)" },
    { 0xFD6F, "Google Fast Pair" },
    { 0xFE9F, "Google Nearby" },
    { 0xFD3A, "Apple Find My" },
    { 0xFD6D, "Amazon Echo" },
    { 0xFEAA, "Eddystone (Google)" },
    { 0xFE0F, "Microsoft" },
    { 0xFDCD, "Samsung SmartThings" },
    { 0xFEDA, "Nike" },
};

static const char* uuid16_lookup(uint16_t uuid) {
    for (int i = 0; i < ARRAY_SIZE(uuid16_table); i++) {
        if (uuid16_table[i].uuid == uuid) {
            return uuid16_table[i].description;
        }
    }
    return "Unknown UUID";
}

typedef struct {
    uint16_t company_id;
    const char* name;
} company_id_desc_t;

// ===== TABLE MANUFACTURERS =====
static const company_id_desc_t company_table[] = {
    { 0x004C, "Apple, Inc." },
    { 0x0006, "Microsoft" },
    { 0x000F, "Broadcom Corporation" },
    { 0x0131, "Google" },
    { 0x0171, "Samsung Electronics" },
    { 0x00E0, "Garmin International" },
    { 0x0001, "Ericsson Technology Licensing" },
    { 0x0075, "Polar Electro Oy" },
    { 0x0059, "Nordic Semiconductor ASA" },
};

static const char* company_lookup(uint16_t company_id) {
    for (int i = 0; i < ARRAY_SIZE(company_table); i++) {
        if (company_table[i].company_id == company_id) {
            return company_table[i].name;
        }
    }
    return "Unknown Manufacturer";
}

void scan(int interval_ms, int window_ms, int length_ms){
    int err;
    struct bt_le_scan_param scan_param = {
        .type     = BT_LE_SCAN_TYPE_PASSIVE,
        .options  = BT_LE_SCAN_OPT_NONE,
        .interval = interval_ms,
        .window   = window_ms,
    };
    err = bt_le_scan_start(&scan_param, device_found);
    if (err) {
        LOG_ERR("Scan failed to start (err %d)", err);
    }
    k_msleep(length_ms);
    err = bt_le_scan_stop();
    if (err) {
        LOG_ERR("Scan failed to stop (err %d)", err);
        return;
    }
}

void device_found(const bt_addr_le_t *addr, int8_t rssi,
                uint8_t type, struct net_buf_simple *ad){
    char addr_str[BT_ADDR_LE_STR_LEN];
    bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
    const char *type_str = "Unknown";
    switch (type) {
        case BT_GAP_ADV_TYPE_ADV_IND:
            type_str = "ADV_IND (Connectable and Scannable)";
            break;
        case BT_GAP_ADV_TYPE_ADV_DIRECT_IND:
            type_str = "ADV_DIRECT_IND (Directed Connectable)";
            break;
        case BT_GAP_ADV_TYPE_ADV_SCAN_IND:
            type_str = "ADV_SCAN_IND (Scannable Only)";
            break;
        case BT_GAP_ADV_TYPE_ADV_NONCONN_IND:
            type_str = "ADV_NONCONN_IND (Non-Connectable)";
            break;
        case BT_GAP_ADV_TYPE_SCAN_RSP:
            type_str = "SCAN_RSP (Scan Response)";
            break;
    }
    LOG_WRN("Device found: %s (RSSI: %d), type: 0x%02X - %s", addr_str, rssi, type, type_str);
    uint8_t index = 0;

    while (index < ad->len) {
        uint8_t field_len = ad->data[index];
        if (field_len == 0 || (index + field_len + 1) > ad->len) {
            LOG_WRN("  Invalid field length or end of buffer");
            break;
        }
        uint8_t field_type = ad->data[index + 1];
        const uint8_t *payload = &ad->data[index + 2];
        uint8_t payload_len = field_len - 1;
        printk("  Field Type: 0x%02X, Length: %d\n", field_type, payload_len);

        switch (field_type) {
            case BT_DATA_FLAGS: {
                printk("    Flags:");
                printk(" 0x%02X", payload[0]);
                if (payload[0] & 0x01) printk(" (LE Limited)");
                if (payload[0] & 0x02) printk(" (LE General)");
                if (payload[0] & 0x04) printk(" (BR/EDR Not Supported)");
                if (payload[0] & 0x08) printk(" (LE + BR/EDR Controller)");
                if (payload[0] & 0x10) printk(" (LE + BR/EDR Host)");
                printk("\n");
                break;
            }
            case BT_DATA_NAME_SHORTENED:
            case BT_DATA_NAME_COMPLETE: {
                char name[32] = {0};
                memcpy(name, payload, MIN(payload_len, sizeof(name) - 1));
                printk("    Name: %s\n", name);
                break;
            }
            case BT_DATA_TX_POWER:
                printk("    TX Power: %d dBm\n", (int8_t)payload[0]);
                break;
            case BT_DATA_UUID16_SOME:
            case BT_DATA_UUID16_ALL:
                for (int i = 0; i + 1 < payload_len; i += 2) {
                    uint16_t uuid = payload[i] | (payload[i + 1] << 8);
                    const char* desc = uuid16_lookup(uuid);
                    printk("    UUID 16-bit: 0x%04X (%s)\n", uuid, desc);
                }
                break;
            case BT_DATA_UUID128_SOME:
            case BT_DATA_UUID128_ALL:
                for (int i = 0; i + 15 < payload_len; i += 16) {
                    printk("    UUID 128-bit: ");
                    for (int j = 0; j < 16; j++) {
                        printk("%02X", payload[i + 15 - j]);
                        if (j == 3 || j == 5 || j == 7 || j == 9) printk("-");
                    }
                    printk("\n");
                }
                break;
            case BT_DATA_SVC_DATA16: {
                if (payload_len < 2) {
                    printk("    Invalid Service Data\n");
                    break;
                }
                uint16_t uuid = payload[0] | (payload[1] << 8);
                const char* desc = uuid16_lookup(uuid);
                printk("    Service Data UUID: 0x%04X (%s)\n    Data: ", uuid, desc);
                for (int i = 2; i < payload_len; i++) {
                    printk("%02X ", payload[i]);
                }
                printk("\n");
                break;
            }
            case BT_DATA_MANUFACTURER_DATA: {
                if (payload_len < 2) {
                    printk("    Invalid Manufacturer Data\n");
                    break;
                }
                uint16_t company_id = payload[0] | (payload[1] << 8);
                const char* name = company_lookup(company_id);
                printk("    Manufacturer ID: 0x%04X (%s)\n    Data: ", company_id, name);
                for (int i = 2; i < payload_len; i++) {
                    printk("%02X ", payload[i]);
                }
                printk("\n");
                break;
            }
            default: {
                printk("    Unknown Type. Raw Data: ");
                for (int i = 0; i < payload_len; i++) {
                    printk("%02X ", payload[i]);
                }
                printk("\n");
                break;
            }
        }
        index += field_len + 1;
    }
}

