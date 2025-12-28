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

#include "safebuffer.h"

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

uint8_t init_rs_protocol(void (*message_received_function)(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source), uint8_t header_byte_1, uint8_t header_byte_2);
uint16_t calculate_CRC16(uint8_t *data, uint32_t len, uint16_t start_value);
int rs_protocol_build_safebuffer(safebuffer_t *sb_out, safebuffer_t *sb_in, uint8_t instance_num);
int rs_protocol_build(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_build_header(uint8_t *out, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_add_packet_header(safebuffer_t *sb, uint8_t *data, uint16_t len, uint8_t instance_num);
int rs_protocol_process_data(uint8_t *data, uint32_t len, uint8_t instance_num, void *source);
safebuffer_t *rs_protocol_build_single_param(uint8_t *buf, uint32_t len, uint8_t instance_num);
safebuffer_t *rs_protocol_build_multiple_params(uint8_t **buf, uint32_t *len, uint32_t num_items, uint8_t instance_num);

#endif /* RS_PROTOCOL_H_ */
