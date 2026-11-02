/*
 * rs_protocol.h
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

#ifndef RS_PROTOCOL_H_
#define RS_PROTOCOL_H_

#include <stdint.h>
#include <stdbool.h>
#include "safebuffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RS_PROTOCOL_HEADER_OVERHEAD                     8     // The number of bytes added to the payload
#define RS_PROTOCOL_INVALID_INSTANCE                    0xff

typedef enum{
  RS_PACKET_VALID_DATA,
  RS_PACKET_ERROR_HEADER_CRC,
  RS_PACKET_ERROR_PACKET_LENGTH,
  RS_PACKET_ERROR_DATA_CRC,
  RS_PACKET_PREAMBLE_RECEIVED
}
rsp_packet_type_t;

struct rs_protocol;

/**
 * Called when a packet was received or an error happened.
 * rsp: The instance that received the packet
 * sb: The packet data for RS_PACKET_VALID_DATA, NULL for the other packet types. The data is in sb->buf and the length
 *     in sb->write_index. sb is freed when the callback returns, unless rs_protocol_take_packet was called.
 * source: The value passed to rs_protocol_process
 */
typedef void (*rs_protocol_cb_t)(struct rs_protocol *rsp, safebuffer_t *sb, rsp_packet_type_t packet_type, void *source);

/**
 * An RS protocol instance. Create it with RS_PROTOCOL_DEFINE, RS_PROTOCOL_DEFINE_STATIC_BUF or rs_protocol_init.
 * Only user_data may be used directly, the other fields are private.
 */
struct rs_protocol {
    void *user_data;                    // Free for the user, for example to find the context in the callback
    rs_protocol_cb_t cb;
    void (*legacy_cb)(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source);
    uint8_t *rx_buf;                    // Static receive buffer, NULL to allocate a buffer for every packet
    uint32_t rx_buf_size;
    safebuffer_t rx_sb;                 // Used with the static receive buffer
    safebuffer_t *sb;                   // Packet being received
    safebuffer_t *delivered_sb;         // Packet passed to the callback, used by rs_protocol_take_packet
    bool delivered_taken;
    uint8_t header_buf[RS_PROTOCOL_HEADER_OVERHEAD];
    uint16_t len;
    uint16_t crc;
    uint8_t state;
    uint8_t header_byte_1;
    uint8_t header_byte_2;
};

#define RS_PROTOCOL_INITIALIZER(_header_byte_1, _header_byte_2, _cb, _rx_buf, _rx_buf_size) \
    { \
        .cb = (_cb), \
        .rx_buf = (_rx_buf), \
        .rx_buf_size = (_rx_buf_size), \
        .header_byte_1 = (_header_byte_1), \
        .header_byte_2 = (_header_byte_2), \
    }

/**
 * Define an instance. A buffer is allocated on the heap for every packet received.
 * Example: RS_PROTOCOL_DEFINE(stm32_link, 'T', 'P', stm32_message_received);
 */
#define RS_PROTOCOL_DEFINE(_name, _header_byte_1, _header_byte_2, _cb) \
    struct rs_protocol _name = RS_PROTOCOL_INITIALIZER(_header_byte_1, _header_byte_2, _cb, NULL, 0)

/**
 * Define an instance with a static receive buffer, no memory is allocated when packets are received. Packets larger
 * than _rx_buf_size are rejected with RS_PACKET_ERROR_PACKET_LENGTH.
 */
#define RS_PROTOCOL_DEFINE_STATIC_BUF(_name, _header_byte_1, _header_byte_2, _cb, _rx_buf_size) \
    static uint8_t _name##_rx_buf[_rx_buf_size]; \
    struct rs_protocol _name = RS_PROTOCOL_INITIALIZER(_header_byte_1, _header_byte_2, _cb, _name##_rx_buf, _rx_buf_size)

// Initialise an instance at run time. rx_buf can be NULL, then a buffer is allocated for every packet received.
int rs_protocol_init(struct rs_protocol *rsp, uint8_t header_byte_1, uint8_t header_byte_2, rs_protocol_cb_t cb,
                     uint8_t *rx_buf, uint32_t rx_buf_size);
// Process received data, the callback is called for every packet and error
int rs_protocol_process(struct rs_protocol *rsp, const uint8_t *data, uint32_t len, void *source);
// Discard a packet that is partly received and start searching for a new header
int rs_protocol_reset(struct rs_protocol *rsp);
// Call from the callback to keep the packet, the caller must free it with safebuffer_free. Return NULL if the packet
// can't be kept, because the instance uses a static receive buffer or the packet is empty. Then copy the data.
safebuffer_t *rs_protocol_take_packet(struct rs_protocol *rsp);

// Build a packet in sb, sb is reset first. Return -ENOMEM if the packet does not fit, then sb is left empty.
int rs_protocol_packet_build(const struct rs_protocol *rsp, safebuffer_t *sb, const uint8_t *data, uint16_t len);
// Build a packet from the data in sb_in
int rs_protocol_packet_build_safebuffer(const struct rs_protocol *rsp, safebuffer_t *sb_out, const safebuffer_t *sb_in);
// Build only the header in out, out must have space for RS_PROTOCOL_HEADER_OVERHEAD bytes
int rs_protocol_packet_build_header(const struct rs_protocol *rsp, uint8_t *out, const uint8_t *data, uint16_t len);
// Add the header for data to sb without resetting sb. Return -ENOMEM if the header does not fit, then nothing is added
int rs_protocol_packet_add_header(const struct rs_protocol *rsp, safebuffer_t *sb, const uint8_t *data, uint16_t len);
// Allocate a safebuffer with a packet containing buf. Free it with safebuffer_free. Return NULL if it failed
safebuffer_t *rs_protocol_packet_alloc_single(const struct rs_protocol *rsp, const uint8_t *buf, uint32_t len);
// Allocate a safebuffer with a packet containing all the buffers one after the other. Free it with safebuffer_free
safebuffer_t *rs_protocol_packet_alloc_multiple(const struct rs_protocol *rsp, const uint8_t *const *buf,
                                                const uint32_t *len, uint32_t num_items);

// CRC-16/XMODEM (polynomial 0x1021, not reflected). Use start_value 0 for the start of the data, otherwise the
// previous CRC value
uint16_t rs_protocol_crc16(const uint8_t *data, uint32_t len, uint16_t start_value);

#if defined(CONFIG_RS_PROTOCOL_LEGACY_API)
// Legacy API, instances are identified by a number. New code should use the functions above.
uint8_t init_rs_protocol(void (*message_received_function)(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source), uint8_t header_byte_1, uint8_t header_byte_2);
uint16_t calculate_CRC16(uint8_t *data, uint32_t len, uint16_t start_value);
int rs_protocol_build_safebuffer(safebuffer_t *sb_out, safebuffer_t *sb_in, uint8_t instance_num);
int rs_protocol_build(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_build_header(uint8_t *out, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_add_packet_header(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_process_data(uint8_t *data, uint32_t len, uint8_t instance_num, void *source);
safebuffer_t *rs_protocol_build_single_param(uint8_t *buf, uint32_t len, uint8_t instance_num);
safebuffer_t *rs_protocol_build_multiple_params(uint8_t **buf, uint32_t *len, uint32_t num_items, uint8_t instance_num);
int rs_protocol_reset_receive(uint8_t instance_num);
// Get the instance behind an instance number, so legacy and new functions can be mixed. NULL if not valid
struct rs_protocol *rs_protocol_get_instance(uint8_t instance_num);
#endif /* CONFIG_RS_PROTOCOL_LEGACY_API */

#ifdef __cplusplus
}
#endif

#endif /* RS_PROTOCOL_H_ */
