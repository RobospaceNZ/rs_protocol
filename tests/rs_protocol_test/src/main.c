#include <zephyr/ztest.h>
#include <zephyr/kernel.h>
#include <string.h>
#include "rs_protocol.h"

#define RX_DATA_SIZE        64

// Everything the callback received
static struct {
    uint32_t valid;
    uint32_t header_crc;
    uint32_t length;
    uint32_t data_crc;
    uint32_t preamble;
    uint8_t data[RX_DATA_SIZE];
    uint32_t len;
} rx;

static uint8_t instance = RS_PROTOCOL_INVALID_INSTANCE;

static void message_received(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source) {
    (void)source;
    switch (packet_type) {
        case RS_PACKET_VALID_DATA:
            rx.valid++;
            rx.len = sb->write_index;
            memcpy(rx.data, sb->buf, (sb->write_index < RX_DATA_SIZE) ? sb->write_index : RX_DATA_SIZE);
            break;
        case RS_PACKET_ERROR_HEADER_CRC:
            rx.header_crc++;
            break;
        case RS_PACKET_ERROR_PACKET_LENGTH:
            rx.length++;
            break;
        case RS_PACKET_ERROR_DATA_CRC:
            rx.data_crc++;
            break;
        case RS_PACKET_PREAMBLE_RECEIVED:
            rx.preamble++;
            break;
    }
}

// The instance is created once, instances can't be freed
static uint8_t get_test_instance(void) {
    if (instance == RS_PROTOCOL_INVALID_INSTANCE) {
        instance = init_rs_protocol(message_received, 'T', 'P');
    }
    return instance;
}

static void rx_reset(void) {
    memset(&rx, 0, sizeof(rx));
    rs_protocol_reset_receive(get_test_instance());
}

// Build a packet into out, return its length or 0 if it could not be built. Asserts can't be used in functions that
// return a value, the tests check the length instead.
static uint32_t build_packet(uint8_t *out, uint32_t out_size, const char *payload, uint16_t len) {
    safebuffer_t sb;

    safebuffer_init(&sb, out, out_size);
    if (rs_protocol_build(&sb, (uint8_t*)payload, len, get_test_instance())) {
        return 0;
    }
    return sb.write_index;
}

ZTEST(rs_protocol, test_rs_protocol_roundtrip)
{
    uint8_t packet[32];
    uint32_t len;

    rx_reset();
    len = build_packet(packet, sizeof(packet), "hello", 5);
    zassert_equal(len, 5 + RS_PROTOCOL_HEADER_OVERHEAD, "Packet should be payload plus header");
    zassert_equal(rs_protocol_process_data(packet, len, get_test_instance(), NULL), 0, "Processing should succeed");
    zassert_equal(rx.preamble, 1, "Preamble should be reported");
    zassert_equal(rx.valid, 1, "One valid packet should be received");
    zassert_equal(rx.len, 5, "Payload length should be 5");
    zassert_equal(memcmp(rx.data, "hello", 5), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_byte_by_byte)
{
    uint8_t packet[32];
    uint32_t len;

    rx_reset();
    len = build_packet(packet, sizeof(packet), "split", 5);
    for (uint32_t i = 0; i < len; i++) {
        rs_protocol_process_data(&packet[i], 1, get_test_instance(), NULL);
    }
    zassert_equal(rx.valid, 1, "A packet received one byte at a time should be valid");
    zassert_equal(memcmp(rx.data, "split", 5), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_empty_packet)
{
    uint8_t packet[32];
    uint32_t len;

    rx_reset();
    len = build_packet(packet, sizeof(packet), NULL, 0);
    zassert_equal(len, RS_PROTOCOL_HEADER_OVERHEAD, "An empty packet is only the header");
    rs_protocol_process_data(packet, len, get_test_instance(), NULL);
    zassert_equal(rx.valid, 1, "An empty packet should be received");
    zassert_equal(rx.len, 0, "Payload length should be 0");
    zassert_equal(rx.length, 0, "An empty packet is not a length error");
}

ZTEST(rs_protocol, test_rs_protocol_lost_byte_resync)
{
    uint8_t stream[64];
    uint8_t packet[32];
    uint32_t a_len;
    uint32_t b_len;

    rx_reset();
    // Packet A loses a payload byte, packet B follows straight after it
    a_len = build_packet(packet, sizeof(packet), "ABCDEFGH", 8);
    memcpy(stream, packet, 10);
    memcpy(&stream[10], &packet[11], a_len - 11);
    a_len--;
    b_len = build_packet(&stream[a_len], sizeof(stream) - a_len, "next", 4);
    rs_protocol_process_data(stream, a_len + b_len, get_test_instance(), NULL);
    zassert_equal(rx.data_crc, 1, "Packet A should fail its data CRC");
    zassert_equal(rx.valid, 1, "Packet B should still be received");
    zassert_equal(memcmp(rx.data, "next", 4), 0, "Packet B payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_corrupted_data_then_packet)
{
    uint8_t stream[64];
    uint32_t a_len;
    uint32_t b_len;

    rx_reset();
    a_len = build_packet(stream, sizeof(stream), "ABCDEFGH", 8);
    stream[12] ^= 0x01;     // Corrupt a payload byte
    b_len = build_packet(&stream[a_len], sizeof(stream) - a_len, "next", 4);
    rs_protocol_process_data(stream, a_len + b_len, get_test_instance(), NULL);
    zassert_equal(rx.data_crc, 1, "Corrupted packet should fail its data CRC");
    zassert_equal(rx.valid, 1, "The packet after it should be received");
    zassert_equal(memcmp(rx.data, "next", 4), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_false_preamble_resync)
{
    uint8_t stream[64];
    uint32_t b_len;

    rx_reset();
    // A header that starts inside the 8 bytes of a false header must still be found
    memcpy(stream, "TPxx", 4);
    b_len = build_packet(&stream[4], sizeof(stream) - 4, "next", 4);
    rs_protocol_process_data(stream, 4 + b_len, get_test_instance(), NULL);
    zassert_true(rx.header_crc >= 1, "The false header should fail its CRC");
    zassert_equal(rx.valid, 1, "The real packet should be received");
    zassert_equal(memcmp(rx.data, "next", 4), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_noise_before_packet)
{
    uint8_t stream[64];
    uint32_t b_len;

    rx_reset();
    memcpy(stream, "\x01TTT\x02P", 6);
    b_len = build_packet(&stream[6], sizeof(stream) - 6, "next", 4);
    rs_protocol_process_data(stream, 6 + b_len, get_test_instance(), NULL);
    zassert_equal(rx.valid, 1, "The packet after the noise should be received");
    zassert_equal(memcmp(rx.data, "next", 4), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_too_long)
{
    uint8_t stream[64];
    uint16_t len = CONFIG_RS_PROTOCOL_MAX_PACKET_SIZE + 1;
    uint16_t crc;
    uint32_t b_len;

    rx_reset();
    // Header with a valid CRC but a length larger than allowed
    stream[0] = 'T';
    stream[1] = 'P';
    stream[2] = len >> 8;
    stream[3] = len & 0xFF;
    stream[4] = 0;
    stream[5] = 0;
    crc = calculate_CRC16(stream, 6, 0);
    stream[6] = crc >> 8;
    stream[7] = crc & 0xFF;
    b_len = build_packet(&stream[8], sizeof(stream) - 8, "next", 4);
    rs_protocol_process_data(stream, 8 + b_len, get_test_instance(), NULL);
    zassert_equal(rx.length, 1, "Too long packet should be a length error");
    zassert_equal(rx.valid, 1, "The packet after it should be received");
    zassert_equal(memcmp(rx.data, "next", 4), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_build_errors)
{
    uint8_t buffer[16];
    safebuffer_t sb;

    safebuffer_init(&sb, buffer, 12);
    zassert_equal(rs_protocol_build(&sb, (uint8_t*)"hello", 5, get_test_instance()), -ENOMEM,
                  "A packet that does not fit should fail");
    zassert_equal(sb.write_index, 0, "Nothing should be added when the packet does not fit");
    zassert_equal(rs_protocol_build(&sb, (uint8_t*)"hell", 4, get_test_instance()), 0, "A packet that fits exactly should succeed");
    zassert_equal(rs_protocol_build(&sb, (uint8_t*)"a", 1, RS_PROTOCOL_INVALID_INSTANCE), -EINVAL, "Invalid instance should fail");
    zassert_equal(rs_protocol_build(NULL, (uint8_t*)"a", 1, get_test_instance()), -EFAULT, "NULL safebuffer should fail");
    zassert_equal(rs_protocol_build(&sb, NULL, 1, get_test_instance()), -EINVAL, "NULL data should fail");

    zassert_is_null(rs_protocol_build_single_param((uint8_t*)"a", 1, RS_PROTOCOL_INVALID_INSTANCE),
                    "Invalid instance should fail without allocating");
    zassert_is_null(rs_protocol_build_single_param((uint8_t*)"a", 0x10000, get_test_instance()),
                    "Payload larger than 16 bits should fail");
    zassert_equal(rs_protocol_process_data((uint8_t*)"a", 1, RS_PROTOCOL_INVALID_INSTANCE, NULL), -EINVAL,
                  "Processing with an invalid instance should fail");
}

ZTEST(rs_protocol, test_rs_protocol_add_packet_header)
{
    uint8_t buffer[16];
    safebuffer_t sb;

    memset(buffer, 0xAA, sizeof(buffer));
    safebuffer_init(&sb, buffer, 10);
    safebuffer_add_data(&sb, (uint8_t*)"abc", 3);
    zassert_equal(rs_protocol_add_packet_header(&sb, (uint8_t*)"x", 1, get_test_instance()), -ENOMEM,
                  "Header that does not fit should fail");
    zassert_equal(sb.write_index, 3, "Nothing should be added when the header does not fit");
    zassert_equal(buffer[10], 0xAA, "Buffer should not have been modified past its end");

    safebuffer_init(&sb, buffer, 8);
    zassert_equal(rs_protocol_add_packet_header(&sb, (uint8_t*)"x", 1, get_test_instance()), 0, "Header that fits should succeed");
    zassert_equal(sb.write_index, RS_PROTOCOL_HEADER_OVERHEAD, "Header should be added");
    zassert_true(sb.full, "Buffer should be full");
    zassert_equal(buffer[8], 0xAA, "Buffer should not have been modified past its end");
}

ZTEST(rs_protocol, test_rs_protocol_params_roundtrip)
{
    uint8_t *bufs[] = {(uint8_t*)"ab", (uint8_t*)"", (uint8_t*)"cd"};
    uint32_t lens[] = {2, 0, 2};
    safebuffer_t *sb;

    rx_reset();
    sb = rs_protocol_build_multiple_params(bufs, lens, 3, get_test_instance());
    zassert_not_null(sb, "Building multiple parameters should succeed");
    rs_protocol_process_data(sb->buf, sb->write_index, get_test_instance(), NULL);
    safebuffer_free(sb);
    zassert_equal(rx.valid, 1, "Packet should be received");
    zassert_equal(rx.len, 4, "Parameters should be joined");
    zassert_equal(memcmp(rx.data, "abcd", 4), 0, "Payload should match");

    rx_reset();
    sb = rs_protocol_build_single_param((uint8_t*)"xyz", 3, get_test_instance());
    zassert_not_null(sb, "Building a single parameter should succeed");
    rs_protocol_process_data(sb->buf, sb->write_index, get_test_instance(), NULL);
    safebuffer_free(sb);
    zassert_equal(rx.valid, 1, "Packet should be received");
    zassert_equal(memcmp(rx.data, "xyz", 3), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_instance_limit)
{
    uint32_t created = 1;   // The test instance

    zassert_not_equal(get_test_instance(), RS_PROTOCOL_INVALID_INSTANCE, "The test instance should be created");
    while (init_rs_protocol(message_received, 'A', 'B') != RS_PROTOCOL_INVALID_INSTANCE) {
        created++;
        zassert_true(created <= CONFIG_RS_PROTOCOL_MAX_INSTANCES, "More instances created than allowed");
    }
    zassert_equal(created, CONFIG_RS_PROTOCOL_MAX_INSTANCES, "All the instances should be available");
    zassert_equal(init_rs_protocol(NULL, 'A', 'B'), RS_PROTOCOL_INVALID_INSTANCE, "A NULL callback should fail");
}

// Tests for the API with struct rs_protocol

static struct {
    uint32_t valid;
    uint32_t length;
    uint32_t data_crc;
    struct rs_protocol *rsp;
    void *user_data;
    bool take;                  // Take the packet in the callback
    safebuffer_t *taken;        // Result of rs_protocol_take_packet
    uint8_t data[RX_DATA_SIZE];
    uint32_t len;
} rx2;

static void handle_message_received(struct rs_protocol *rsp, safebuffer_t *sb, rsp_packet_type_t packet_type,
                                    void *source) {
    (void)source;
    rx2.rsp = rsp;
    rx2.user_data = rsp->user_data;
    switch (packet_type) {
        case RS_PACKET_VALID_DATA:
            rx2.valid++;
            rx2.len = sb->write_index;
            memcpy(rx2.data, sb->buf, (sb->write_index < RX_DATA_SIZE) ? sb->write_index : RX_DATA_SIZE);
            if (rx2.take) {
                rx2.taken = rs_protocol_take_packet(rsp);
            }
            break;
        case RS_PACKET_ERROR_PACKET_LENGTH:
            rx2.length++;
            break;
        case RS_PACKET_ERROR_DATA_CRC:
            rx2.data_crc++;
            break;
        default:
            break;
    }
}

RS_PROTOCOL_DEFINE(defined_rsp, 'R', 'S', handle_message_received);
RS_PROTOCOL_DEFINE_STATIC_BUF(static_rsp, 'S', 'B', handle_message_received, 16);

static void rx2_reset(void) {
    memset(&rx2, 0, sizeof(rx2));
    rs_protocol_reset(&defined_rsp);
    rs_protocol_reset(&static_rsp);
}

// Build a packet for rsp into out, return its length or 0 if it could not be built
static uint32_t build_handle_packet(struct rs_protocol *rsp, uint8_t *out, uint32_t out_size, const char *payload, uint16_t len) {
    safebuffer_t sb;

    safebuffer_init(&sb, out, out_size);
    if (rs_protocol_packet_build(rsp, &sb, (const uint8_t*)payload, len)) {
        return 0;
    }
    return sb.write_index;
}

ZTEST(rs_protocol, test_rs_protocol_crc16)
{
    uint16_t crc;

    // Check value of CRC-16/XMODEM, the same with the lookup table and with Zephyr's crc16_itu_t
    zassert_equal(rs_protocol_crc16((const uint8_t*)"123456789", 9, 0), 0x31C3, "CRC-16/XMODEM check value should match");
    crc = rs_protocol_crc16((const uint8_t*)"1234", 4, 0);
    crc = rs_protocol_crc16((const uint8_t*)"56789", 5, crc);
    zassert_equal(crc, 0x31C3, "CRC calculated in parts should match");
    zassert_equal(rs_protocol_crc16(NULL, 5, 0x1234), 0x1234, "NULL data should return the start value");
    zassert_equal(calculate_CRC16((uint8_t*)"123456789", 9, 0), 0x31C3, "Legacy CRC function should match");
}

ZTEST(rs_protocol, test_rs_protocol_defined_instance)
{
    uint8_t packet[32];
    uint32_t len;
    int context = 42;

    rx2_reset();
    defined_rsp.user_data = &context;
    len = build_handle_packet(&defined_rsp, packet, sizeof(packet), "hello", 5);
    zassert_equal(packet[0], 'R', "First header byte of the instance should be used");
    zassert_equal(packet[1], 'S', "Second header byte of the instance should be used");
    zassert_equal(rs_protocol_process(&defined_rsp, packet, len, NULL), 0, "Processing should succeed");
    zassert_equal(rx2.valid, 1, "Packet should be received");
    zassert_equal(rx2.rsp, &defined_rsp, "Callback should get the instance");
    zassert_equal(rx2.user_data, &context, "user_data should be available in the callback");
    zassert_equal(memcmp(rx2.data, "hello", 5), 0, "Payload should match");
    defined_rsp.user_data = NULL;
}

ZTEST(rs_protocol, test_rs_protocol_take_packet)
{
    uint8_t packet[32];
    uint32_t len;

    rx2_reset();
    zassert_is_null(rs_protocol_take_packet(&defined_rsp), "Take outside the callback should fail");
    rx2.take = true;
    len = build_handle_packet(&defined_rsp, packet, sizeof(packet), "keep", 4);
    rs_protocol_process(&defined_rsp, packet, len, NULL);
    zassert_not_null(rx2.taken, "The packet should be taken in the callback");
    zassert_equal(rx2.taken->write_index, 4, "Taken packet should keep its length");
    zassert_equal(memcmp(rx2.taken->buf, "keep", 4), 0, "Taken packet should keep its data after the callback");
    safebuffer_free(rx2.taken);

    // An empty packet is on the stack, it can't be taken
    rx2.taken = NULL;
    len = build_handle_packet(&defined_rsp, packet, sizeof(packet), NULL, 0);
    rs_protocol_process(&defined_rsp, packet, len, NULL);
    zassert_equal(rx2.valid, 2, "Empty packet should be received");
    zassert_is_null(rx2.taken, "An empty packet can't be taken");
}

ZTEST(rs_protocol, test_rs_protocol_static_buffer)
{
    uint8_t stream[64];
    uint8_t packet[40];
    uint32_t len;
    uint32_t b_len;

    rx2_reset();
    rx2.take = true;
    len = build_handle_packet(&static_rsp, packet, sizeof(packet), "0123456789", 10);
    rs_protocol_process(&static_rsp, packet, len, NULL);
    zassert_equal(rx2.valid, 1, "Packet should be received in the static buffer");
    zassert_equal(memcmp(rx2.data, "0123456789", 10), 0, "Payload should match");
    zassert_is_null(rx2.taken, "A packet in the static buffer can't be taken");

    len = build_handle_packet(&static_rsp, packet, sizeof(packet), "0123456789ABCDEFG", 17);
    rs_protocol_process(&static_rsp, packet, len, NULL);
    zassert_equal(rx2.length, 1, "Packet larger than the static buffer should be rejected");

    // Resync with the static buffer, the next packet is found in the data of the failed packet
    rx2_reset();
    len = build_handle_packet(&static_rsp, packet, sizeof(packet), "ABCDEFGHIJKL", 12);
    memcpy(stream, packet, 10);
    memcpy(&stream[10], &packet[11], len - 11);
    len--;
    b_len = build_handle_packet(&static_rsp, &stream[len], sizeof(stream) - len, "next", 4);
    rs_protocol_process(&static_rsp, stream, len + b_len, NULL);
    zassert_equal(rx2.data_crc, 1, "Packet with a lost byte should fail");
    zassert_equal(rx2.valid, 1, "The next packet should still be received");
    zassert_equal(memcmp(rx2.data, "next", 4), 0, "Payload should match");
}

ZTEST(rs_protocol, test_rs_protocol_init_runtime)
{
    struct rs_protocol rsp;
    uint8_t buf[8];
    uint8_t packet[32];
    uint32_t len;

    zassert_equal(rs_protocol_init(NULL, 'A', 'B', handle_message_received, NULL, 0), -EFAULT, "NULL instance should fail");
    zassert_equal(rs_protocol_init(&rsp, 'A', 'B', NULL, NULL, 0), -EINVAL, "NULL callback should fail");
    zassert_equal(rs_protocol_init(&rsp, 'A', 'B', handle_message_received, NULL, 8), -EINVAL,
                  "A size without a buffer should fail");
    zassert_equal(rs_protocol_init(&rsp, 'A', 'B', handle_message_received, buf, sizeof(buf)), 0, "Init should succeed");

    rx2_reset();
    len = build_handle_packet(&rsp, packet, sizeof(packet), "run", 3);
    rs_protocol_process(&rsp, packet, len, NULL);
    zassert_equal(rx2.valid, 1, "Packet should be received");
    zassert_equal(rx2.rsp, &rsp, "Callback should get the instance");
    zassert_equal(rs_protocol_process(NULL, packet, len, NULL), -EFAULT, "NULL instance should fail");
}

ZTEST(rs_protocol, test_rs_protocol_alloc_and_legacy_mix)
{
    const uint8_t *bufs[] = {(const uint8_t*)"ab", (const uint8_t*)"cd"};
    const uint32_t lens[] = {2, 2};
    struct rs_protocol *legacy;
    safebuffer_t *sb;

    rx2_reset();
    sb = rs_protocol_packet_alloc_multiple(&defined_rsp, bufs, lens, 2);
    zassert_not_null(sb, "Allocating a packet should succeed");
    rs_protocol_process(&defined_rsp, sb->buf, sb->write_index, NULL);
    safebuffer_free(sb);
    zassert_equal(memcmp(rx2.data, "abcd", 4), 0, "Payload should match");
    zassert_is_null(rs_protocol_packet_alloc_single(NULL, (const uint8_t*)"a", 1), "NULL instance should fail");

    // A legacy instance can be used with the new functions
    legacy = rs_protocol_get_instance(get_test_instance());
    zassert_not_null(legacy, "Legacy instance should be found");
    zassert_is_null(rs_protocol_get_instance(RS_PROTOCOL_INVALID_INSTANCE), "Invalid instance number should fail");
    rx_reset();
    sb = rs_protocol_packet_alloc_single(legacy, (const uint8_t*)"mix", 3);
    zassert_not_null(sb, "Allocating a packet should succeed");
    rs_protocol_process_data(sb->buf, sb->write_index, get_test_instance(), NULL);
    safebuffer_free(sb);
    zassert_equal(rx.valid, 1, "Legacy callback should receive the packet");
    zassert_equal(memcmp(rx.data, "mix", 3), 0, "Payload should match");
}

ZTEST_SUITE(rs_protocol, NULL, NULL, NULL, NULL, NULL);
