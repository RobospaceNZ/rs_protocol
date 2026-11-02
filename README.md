# RS Protocol

## Description

This protocol has an 8 byte header built up as follows:
| Byte | Description        |
|------|--------------------|
| 0    | Header byte 1      |
| 1    | Header byte 2      |
| 2    | Message length MSB |
| 3    | Message length LSB |
| 4    | Message CRC MSB    |
| 5    | Message CRC LSB    |
| 6    | Header CRC MSB     |
| 7    | Header CRC LSB     |

The CRC is CRC-16/XMODEM (polynomial 0x1021, initial value 0). The header CRC is calculated over bytes 0 to 5.
This is the same packet format as the TpProtocolV2 library used on STM32.

Set CONFIG_RS_PROTOCOL_MAX_INSTANCES to the maximum number of instances, it defaults to 4.

Set CONFIG_RS_PROTOCOL_MAX_PACKET_SIZE to the largest payload that will be received, it defaults to 4096. Larger
packets are rejected with RS_PACKET_ERROR_PACKET_LENGTH before memory is allocated for them. Empty packets, with a
payload length of 0, are allowed.

Use init_rs_protocol to create a new instance. This function specifies the values of the 2 header bytes. Instances can
be created from different threads, but each instance must only be used by one thread.

If a packet fails its header or data CRC, the bytes received after its first header byte are processed again. When a
byte went missing, the next packet started inside the failed packet, so it is still received.

The safebuffer passed to the callback with RS_PACKET_VALID_DATA is freed when the callback returns, copy the data if it
is needed later.

The build functions return -ENOMEM if the packet does not fit in the safebuffer, then no partial packet is built.
rs_protocol_build_single_param and rs_protocol_build_multiple_params return NULL if the instance is not valid or the
payload is larger than 65535 bytes.

The callback function typically looks like this:

```
static void rsp_message_received_function(safebuffer_t *sb, rsp_packet_type_t packet_type, void *source) {
    switch (packet_type) {
        case RS_PACKET_PREAMBLE_RECEIVED:
            break;
        case RS_PACKET_VALID_DATA:
            // Process data received
            // Data in sb->buf
            // Size of buffer in sb->write_index
            break;
        case RS_PACKET_ERROR_HEADER_CRC:
            LOG_ERR("Header CRC error");
            break;
        case RS_PACKET_ERROR_PACKET_LENGTH:
            LOG_ERR("Packet length error");
            break;
        case RS_PACKET_ERROR_DATA_CRC:
            LOG_ERR("Data CRC error");
            break;
        default:
            LOG_ERR("Unknown packet type: %d", packet_type);
            break;
    }
}

static void thread_fn(void) {
    uint8_t rsp_instance;
    
    rsp_instance = init_rs_protocol(rsp_message_received_function, 'R', 'S');

    // data received in buf, size in len
    rs_protocol_process_data(buf, len, rsp_instance, NULL);
}
```

This library has a dependency on safebuffer:

https://github.com/RobospaceNZ/safebuffer

rs_protocol V1.1.0 works with safebuffer V1.0.2 and V2.0.0. Older versions of rs_protocol set `sb->p_gp`, which was
removed in safebuffer V2.0.0, so they only work with safebuffer V1.x.

## Import into Zephyr

This code can be cloned as part of the user's code, but can also be cloned into your Zephyr library. The advantage of this is, if it is cloned into Zephyr once, it will be available to all your Zephyr projects.

For the examples below, we are assuming Nordic NCS 2.9.0. Please adjust to your version.

If you are using Nordic's NCS, open west.yml located at:<br>
C:\ncs\v2.9.0\nrf\west.yml

Under remotes, add:
```
    - name: rs_protocol
      url-base: https://github.com/RobospaceNZ
```

Under projects, add:
```
    - name: rs_protocol
      remote: rs_protocol
      revision: V1.1.0
      path: modules/lib/rs_protocol
```

Open command prompt in C:\ncs\v2.9.0. Remember to update b620d30767 if you use a different NCS (See C:\ncs\toolchains\toolchains.json for the version codes). Run the following:
```
SET PATH=C:\ncs\toolchains\b620d30767\opt\bin;C:\ncs\toolchains\b620d30767\opt\bin\Scripts;%PATH%
west update
```

The rs_protocol code will be located at:<br>
C:\ncs\v2.9.0\modules\lib\rs_protocol

Add the following to your CMakeLists.txt file:
```
set(RS_PROTOCOL_SRC ${ZEPHYR_BASE}/../modules/lib/rs_protocol)
add_subdirectory(${RS_PROTOCOL_SRC} ${CMAKE_BINARY_DIR}/rs_protocol_build)
```

Add the following to your Kconfig file:
```
rsource "${ZEPHYR_BASE}/../modules/lib/rs_protocol/Kconfig.rs_protocol"
```