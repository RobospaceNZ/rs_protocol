/*
 * rs_protocol.c
 *
 * Copyright (c) 2025 Hubert Jetschko
 *
 * This file is licensed under the MIT License.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <zephyr/kernel.h>
#include <string.h>
#include <errno.h>
#include "rs_protocol.h"
#include "safebuffer.h"

#define HEADER_BUF_SIZE                                 8
#define HEADER_CRC_CALC_SIZE                            6
#define MAX_PAYLOAD_LEN                                 0xFFFF  // The length in the header is 16 bits
// After an error the bytes received after the first header byte are processed again, because a real packet can start
// in them. A packet found that way can fail again, this limits how many times that is done.
#define MAX_RESYNC_DEPTH                                4

typedef enum {
    RS_HEADER_BYTE_1,
    RS_HEADER_BYTE_2,
    RS_LEN_BYTE_1,
    RS_LEN_BYTE_2,
    RS_DATA_CRC_BYTE_1,
    RS_DATA_CRC_BYTE_2,
    RS_HEADER_CRC_BYTE_1,
    RS_HEADER_CRC_BYTE_2,
    RS_DATA
}
rec_state_t;

typedef struct {
    void (*message_received_cb)(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source);
    uint8_t header_buf[HEADER_BUF_SIZE];     // Collect the bytes for the header to make it easier to calculate the header CRC
    safebuffer_t *sb;
    uint16_t len;
    uint16_t crc;
    rec_state_t state;
    uint8_t header_byte_1;
    uint8_t header_byte_2;
}
rs_protocol_data_t;

static uint8_t rs_protocol_num_instances = 0;
static rs_protocol_data_t *rs_protocol_data[CONFIG_RS_PROTOCOL_MAX_INSTANCES];
static struct k_spinlock instance_lock;

static const uint16_t crcTabccitt[] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

// Return the instance data, NULL if the instance number is not valid
static rs_protocol_data_t *get_instance(uint8_t instance_num) {
    if (instance_num >= rs_protocol_num_instances) {
        return NULL;   // index out of range
    }
    return rs_protocol_data[instance_num];
}

// Initialise variables used for protocol
// Return instance number for this protocol, RS_PROTOCOL_INVALID_INSTANCE if no more instances can be created
uint8_t init_rs_protocol(void (*message_received_function)(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source), uint8_t header_byte_1, uint8_t header_byte_2) {
    rs_protocol_data_t *rsp;
    uint8_t instance_num;
    k_spinlock_key_t key;

    if (message_received_function == NULL) {
        return RS_PROTOCOL_INVALID_INSTANCE;
    }
    // Allocate first, so a failed allocation does not use up an instance
    rsp = k_malloc(sizeof(rs_protocol_data_t));
    if (rsp == NULL) {
        return RS_PROTOCOL_INVALID_INSTANCE;
    }
    rsp->message_received_cb = message_received_function;
    rsp->sb = NULL;
    rsp->state = RS_HEADER_BYTE_1;
    rsp->header_byte_1 = header_byte_1;
    rsp->header_byte_2 = header_byte_2;

    // Instances can be created from different threads at the same time
    key = k_spin_lock(&instance_lock);
    if (rs_protocol_num_instances >= CONFIG_RS_PROTOCOL_MAX_INSTANCES) {
        k_spin_unlock(&instance_lock, key);
        k_free(rsp);
        return RS_PROTOCOL_INVALID_INSTANCE;
    }
    instance_num = rs_protocol_num_instances;
    rs_protocol_data[instance_num] = rsp;
    rs_protocol_num_instances++;    // Only count the instance once it can be used
    k_spin_unlock(&instance_lock, key);
    return instance_num;
}

// Calculate a new CRC value
// data: Buffer containing the data from which the CRC will be calculated
// len: Number of bytes in the buffer
// start_value: For the start of the buffer this will be the initialisation value, otherwise it will be the previous crc value
uint16_t calculate_CRC16(uint8_t *data, uint32_t len, uint16_t start_value) {
    uint16_t crc;
    uint16_t tmp;
    uint16_t short_c;
    size_t a;

    crc = start_value;
    if (data != NULL) {
        for (a = 0; a < len; a++) {
            short_c = 0x00ff & (unsigned short)*data;
            tmp     = (crc >> 8) ^ short_c;
            crc     = (crc << 8) ^ crcTabccitt[tmp];
            data++;
        }
    }
    return crc;
}

// Build a protocol packet that can be sent to another device using a Safe Buffer as input
int rs_protocol_build_safebuffer(safebuffer_t *sb_out, safebuffer_t *sb_in, uint8_t instance_num) {
    if (sb_in == NULL) {
        return -EFAULT;
    }
    if (sb_in->write_index > MAX_PAYLOAD_LEN) {
        return -EINVAL;   // Does not fit in the 16 bit length
    }
    return rs_protocol_build(sb_out, sb_in->buf, (uint16_t)sb_in->write_index, instance_num);
}

// Build a protocol packet that can be sent to another device
// sb: Pointer to a safe buffer that will be used for building the protocol. It must be initialised before use
// Return -ENOMEM if the packet does not fit in sb, then sb is left empty
int rs_protocol_build(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num) {
    uint16_t crc;
    rs_protocol_data_t *rsp;

    rsp = get_instance(instance_num);
    if (rsp == NULL) {
        return -EINVAL;
    }
    if (sb == NULL) {
        return -EFAULT;
    }
    if ((data == NULL) && len) {
        return -EINVAL;
    }
    safebuffer_reset(sb);
    if (safebuffer_get_data_left_count(sb) < (uint32_t)len + HEADER_BUF_SIZE) {
        // Don't build a packet that is cut short, its header would claim more data than was added
        return -ENOMEM;
    }
    safebuffer_add_char(sb, rsp->header_byte_1);
    safebuffer_add_char(sb, rsp->header_byte_2);
    safebuffer_add_char(sb, (uint8_t)(len >> 8));
    safebuffer_add_char(sb, (uint8_t)(len & 0xff));
    crc = calculate_CRC16(data, len, 0);
    safebuffer_add_char(sb, (uint8_t)(crc >> 8));
    safebuffer_add_char(sb, (uint8_t)(crc & 0xff));
    crc = calculate_CRC16(sb->buf, sb->write_index, 0);
    safebuffer_add_char(sb, (uint8_t)(crc >> 8));
    safebuffer_add_char(sb, (uint8_t)(crc & 0xff));
    safebuffer_add_data(sb, data, len);
    return 0;
}

// Build a protocol, this is used to build the header in place. out must have space for RS_PROTOCOL_HEADER_OVERHEAD bytes
int rs_protocol_build_header(uint8_t *out, uint8_t *data, uint16_t len, uint8_t instance_num) {
    uint8_t *p = out;
    uint16_t crc;
    rs_protocol_data_t *rsp;

    rsp = get_instance(instance_num);
    if (rsp == NULL) {
        return -EINVAL;
    }
    if (out == NULL) {
        return -EFAULT;
    }
    if ((data == NULL) && len) {
        return -EINVAL;
    }
    *p++ = rsp->header_byte_1;
    *p++ = rsp->header_byte_2;
    *p++ = (uint8_t)(len >> 8);
    *p++ = (uint8_t)(len & 0xff);
    crc = calculate_CRC16(data, len, 0);
    *p++ = (uint8_t)(crc >> 8);
    *p++ = (uint8_t)(crc & 0xff);
    crc = calculate_CRC16(out, HEADER_CRC_CALC_SIZE, 0);
    *p++ = (uint8_t)(crc >> 8);
    *p++ = (uint8_t)(crc & 0xff);
    return 0;
}

// Build a protocol packet header and add it to a safe buffer. The safe buffer is not reset before adding the header.
// Return -ENOMEM if there is no space for the whole header, then nothing is added
int rs_protocol_add_packet_header(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num) {
    rs_protocol_data_t *rsp;
    int err;

    rsp = get_instance(instance_num);
    if (rsp == NULL) {
        return -EINVAL;
    }
    if (sb == NULL) {
        return -EFAULT;
    }
    if (safebuffer_get_data_left_count(sb) < HEADER_BUF_SIZE) {
        return -ENOMEM;
    }
    err = rs_protocol_build_header(&sb->buf[sb->write_index], data, len, instance_num);
    if (err) {
        return err;
    }
    sb->write_index += HEADER_BUF_SIZE;
    if (sb->write_index >= sb->len) {
        sb->full = true;
    }
    return 0;
}

// Build a protocol packet with a single parameter that can be sent to another device
// Return safebuffer must be freed by the caller, NULL if it could not be built
safebuffer_t *rs_protocol_build_single_param(uint8_t *buf, uint32_t len, uint8_t instance_num) {
    safebuffer_t *sb;

    if ((get_instance(instance_num) == NULL) || (len > MAX_PAYLOAD_LEN) || ((buf == NULL) && len)) {
        return NULL;
    }
    sb = safebuffer_malloc(len + HEADER_BUF_SIZE);
    if (sb) {
        if (len) {
            memcpy(sb->buf + HEADER_BUF_SIZE, buf, len);
        }
        rs_protocol_build_header(sb->buf, buf, (uint16_t)len, instance_num);
        sb->write_index = len + HEADER_BUF_SIZE;
        sb->len = sb->write_index;
        sb->full = true;
    }
    return sb;
}

// Build a protocol packet with multiple parameters that can be sent to another device
// Return safebuffer must be freed by the caller, NULL if it could not be built
safebuffer_t *rs_protocol_build_multiple_params(uint8_t **buf, uint32_t *len, uint32_t num_items, uint8_t instance_num) {
    uint32_t payload_len = 0;
    uint32_t i;

    if ((get_instance(instance_num) == NULL) || (num_items && ((buf == NULL) || (len == NULL)))) {
        return NULL;
    }
    for (i = 0; i < num_items; i++) {
        if ((buf[i] == NULL) && len[i]) {
            return NULL;
        }
        if (len[i] > MAX_PAYLOAD_LEN - payload_len) {
            return NULL;   // Does not fit in the 16 bit length
        }
        payload_len += len[i];
    }
    safebuffer_t *sb = safebuffer_malloc(payload_len + HEADER_BUF_SIZE);
    if (sb) {
        uint8_t *p = &sb->buf[HEADER_BUF_SIZE];
        for (i = 0; i < num_items; i++) {
            if (len[i]) {
                memcpy(p, buf[i], len[i]);
                p += len[i];
            }
        }
        rs_protocol_build_header(sb->buf, &sb->buf[HEADER_BUF_SIZE], (uint16_t)payload_len, instance_num);
        sb->write_index = payload_len + HEADER_BUF_SIZE;
        sb->len = sb->write_index;
        sb->full = true;
    }
    return sb;
}

int rs_protocol_reset_receive(uint8_t instance_num) {
    rs_protocol_data_t *rsp;

    rsp = get_instance(instance_num);
    if (rsp == NULL) {
        return -EINVAL;
    }
    rsp->state = RS_HEADER_BYTE_1;
    if (rsp->sb) {
        safebuffer_free(rsp->sb);
        rsp->sb = NULL;
    }
    return 0;
}

static void process_bytes(rs_protocol_data_t *rsp, uint8_t *data, uint32_t len, void *source, uint8_t depth);

// Called when a packet failed. A byte might have been lost, then the real start of the next packet can be in the bytes
// already received. Process them again, starting after the first header byte so the same packet is not found again.
// payload: Data of the failed packet, NULL if the header was not valid
static void resync(rs_protocol_data_t *rsp, uint8_t *payload, uint32_t payload_len, void *source, uint8_t depth) {
    uint8_t header[HEADER_BUF_SIZE - 1];

    rsp->state = RS_HEADER_BYTE_1;
    if (depth >= MAX_RESYNC_DEPTH) {
        return;
    }
    // header_buf changes while processing, use a copy
    memcpy(header, &rsp->header_buf[1], sizeof(header));
    process_bytes(rsp, header, sizeof(header), source, depth + 1);
    if (payload_len) {
        process_bytes(rsp, payload, payload_len, source, depth + 1);
    }
}

// A valid packet was received, pass it to the callback
static void packet_received(rs_protocol_data_t *rsp, void *source) {
    safebuffer_t *sb = rsp->sb;

    // The callback may call rs_protocol_reset_receive or process more data, so the packet is taken out of rsp first
    rsp->sb = NULL;
    rsp->state = RS_HEADER_BYTE_1;
    rsp->message_received_cb(sb, RS_PACKET_VALID_DATA, source);
    safebuffer_free(sb);
}

static void process_bytes(rs_protocol_data_t *rsp, uint8_t *data, uint32_t len, void *source, uint8_t depth) {
    uint32_t i;
    uint8_t c;

    for (i = 0; i < len; i++) {
        c = *data++;
        switch(rsp->state) {
            case RS_HEADER_BYTE_1:
                if (c == rsp->header_byte_1) {
                    rsp->state = RS_HEADER_BYTE_2;
                }
                break;
            case RS_HEADER_BYTE_2:
                if (c == rsp->header_byte_2) {
                    rsp->state = RS_LEN_BYTE_1;
                    rsp->message_received_cb(NULL, RS_PACKET_PREAMBLE_RECEIVED, source);
                } else if (c != rsp->header_byte_1) {
                    rsp->state = RS_HEADER_BYTE_1;
                }
                break;
            case RS_LEN_BYTE_1:
                rsp->len = c;
                rsp->len <<= 8;
                rsp->state = RS_LEN_BYTE_2;
                rsp->header_buf[0] = rsp->header_byte_1;
                rsp->header_buf[1] = rsp->header_byte_2;
                rsp->header_buf[2] = c;
                break;
            case RS_LEN_BYTE_2:
                rsp->len |= c;
                rsp->header_buf[3] = c;
                rsp->state = RS_DATA_CRC_BYTE_1;
                break;
            case RS_DATA_CRC_BYTE_1:
                rsp->header_buf[4] = c;
                rsp->state = RS_DATA_CRC_BYTE_2;
                break;
            case RS_DATA_CRC_BYTE_2:
                rsp->header_buf[5] = c;
                rsp->state = RS_HEADER_CRC_BYTE_1;
                break;
            case RS_HEADER_CRC_BYTE_1:
                rsp->crc = c;
                rsp->crc <<= 8;
                rsp->header_buf[6] = c;
                rsp->state = RS_HEADER_CRC_BYTE_2;
                break;
            case RS_HEADER_CRC_BYTE_2:
                rsp->crc |= c;
                rsp->header_buf[7] = c;
                if (rsp->crc != calculate_CRC16(rsp->header_buf, HEADER_CRC_CALC_SIZE, 0)) {
                    rsp->message_received_cb(NULL, RS_PACKET_ERROR_HEADER_CRC, source);
                    resync(rsp, NULL, 0, source, depth);
                    break;
                }
                if (rsp->sb) {
                    safebuffer_free(rsp->sb);
                    rsp->sb = NULL;
                }
                if (rsp->len > CONFIG_RS_PROTOCOL_MAX_PACKET_SIZE) {
                    // Too large, reject it before trying to allocate memory for it
                    rsp->message_received_cb(NULL, RS_PACKET_ERROR_PACKET_LENGTH, source);
                    resync(rsp, NULL, 0, source, depth);
                    break;
                }
                if (rsp->len == 0) {
                    // Empty packet, there is no data to wait for
                    safebuffer_t empty;
                    uint16_t data_crc = ((uint16_t)rsp->header_buf[4] << 8) | rsp->header_buf[5];

                    rsp->state = RS_HEADER_BYTE_1;
                    if (data_crc == calculate_CRC16(NULL, 0, 0)) {
                        safebuffer_init(&empty, NULL, 0);
                        rsp->message_received_cb(&empty, RS_PACKET_VALID_DATA, source);
                    } else {
                        rsp->message_received_cb(NULL, RS_PACKET_ERROR_DATA_CRC, source);
                        resync(rsp, NULL, 0, source, depth);
                    }
                    break;
                }
                rsp->sb = safebuffer_malloc(rsp->len);
                if (rsp->sb == NULL) {
                    // Unable to allocate enough memory for the message
                    rsp->message_received_cb(NULL, RS_PACKET_ERROR_PACKET_LENGTH, source);
                    resync(rsp, NULL, 0, source, depth);
                    break;
                }
                rsp->state = RS_DATA;
                break;
            case RS_DATA:
                safebuffer_add_char(rsp->sb, c);
                if (rsp->sb->write_index >= rsp->len) {
                    rsp->crc = rsp->header_buf[4];
                    rsp->crc <<= 8;
                    rsp->crc |= rsp->header_buf[5];
                    if (rsp->crc == calculate_CRC16(rsp->sb->buf, rsp->len, 0)) {
                        packet_received(rsp, source);
                    } else {
                        // The data of the failed packet is processed again, the next packet can start in it
                        safebuffer_t *failed = rsp->sb;

                        rsp->sb = NULL;
                        rsp->message_received_cb(NULL, RS_PACKET_ERROR_DATA_CRC, source);
                        resync(rsp, failed->buf, failed->write_index, source, depth);
                        safebuffer_free(failed);
                    }
                }
                break;
        }
    }
}

// Process data that was received. If a complete message was received then the callback function will be called.
// If a packet fails, the bytes after the start of the failed packet are processed again, so the next packet is not
// lost when a byte went missing.
int rs_protocol_process_data(uint8_t *data, uint32_t len, uint8_t instance_num, void *source) {
    rs_protocol_data_t *rsp;

    rsp = get_instance(instance_num);
    if (rsp == NULL) {
        return -EINVAL;
    }
    if ((data == NULL) && len) {
        return -EINVAL;
    }
    process_bytes(rsp, data, len, source, 0);
    return 0;
}
