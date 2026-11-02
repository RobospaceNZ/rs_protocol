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

## How to use

An instance is a `struct rs_protocol`. Define it with the 2 header bytes and the callback that is called for every
packet received:

```
static void message_received(struct rs_protocol *rsp, safebuffer_t *sb, rsp_packet_type_t packet_type, void *source) {
    switch (packet_type) {
        case RS_PACKET_PREAMBLE_RECEIVED:
            break;
        case RS_PACKET_VALID_DATA:
            // Process data received
            // Data in sb->buf
            // Size of the data in sb->write_index
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

RS_PROTOCOL_DEFINE(stm32_link, 'T', 'P', message_received);

static void thread_fn(void) {
    // Data received in buf, size in len
    rs_protocol_process(&stm32_link, buf, len, NULL);

    // Send a packet
    uint8_t out[RS_PROTOCOL_HEADER_OVERHEAD + 16];
    safebuffer_t sb;
    safebuffer_init(&sb, out, sizeof(out));
    if (rs_protocol_packet_build(&stm32_link, &sb, payload, payload_len) == 0) {
        // Send sb.buf, length sb.write_index
    }
}
```

`source` is the value passed to `rs_protocol_process`, for example to tell which uart the data came from.
`rsp->user_data` is free for your own use, for example to find a context structure in the callback.

An instance can also be initialised at run time with `rs_protocol_init`, for example when it is part of another
structure. Each instance must only be used by one thread.

### Receive buffers

By default a buffer is allocated on the heap for every packet received. It is passed to the callback and freed when the
callback returns. To keep the packet without copying it, call `rs_protocol_take_packet` in the callback. It returns
the safebuffer, which you must free with `safebuffer_free` when you are finished with it:
```
case RS_PACKET_VALID_DATA: {
    safebuffer_t *packet = rs_protocol_take_packet(rsp);
    // Pass packet to another thread, it frees it
    break;
}
```

To avoid allocating memory, define the instance with a static receive buffer. Packets larger than the buffer are
rejected with RS_PACKET_ERROR_PACKET_LENGTH:
```
RS_PROTOCOL_DEFINE_STATIC_BUF(stm32_link, 'T', 'P', message_received, 512);
```
A packet in a static buffer is overwritten by the next packet, so `rs_protocol_take_packet` returns NULL and the data
must be copied if it is needed after the callback. The same is true for empty packets.

### Errors

If a packet fails its header or data CRC, the bytes received after its first header byte are processed again. When a
byte went missing, the next packet started inside the failed packet, so it is still received.

`rs_protocol_reset` discards a packet that is partly received, for example after a uart error.

The build functions return -ENOMEM if the packet does not fit in the safebuffer, then no partial packet is built.
`rs_protocol_packet_alloc_single` and `rs_protocol_packet_alloc_multiple` return NULL if the payload is larger than
65535 bytes or no memory is available.

### Configuration

| Option                             | Default | Description |
|------------------------------------|---------|-------------|
| CONFIG_RS_PROTOCOL_MAX_PACKET_SIZE | 4096    | Largest payload received. Larger packets are rejected before memory is allocated. Empty packets are allowed. |
| CONFIG_RS_PROTOCOL_CRC_TABLE       | n       | Calculate the CRC with a 512 byte lookup table, which is faster. Otherwise Zephyr's crc16_itu_t is used, which gives the same CRC. |
| CONFIG_RS_PROTOCOL_LEGACY_API      | y       | Keep the V1.x functions that use instance numbers. |
| CONFIG_RS_PROTOCOL_MAX_INSTANCES   | 4       | Number of instances that can be created with init_rs_protocol. |

### Legacy API

Code written for V1.x still compiles while CONFIG_RS_PROTOCOL_LEGACY_API is enabled. `init_rs_protocol` returns an
instance number that is passed to the other legacy functions:

| Legacy function                    | New function                          |
|------------------------------------|---------------------------------------|
| init_rs_protocol                   | RS_PROTOCOL_DEFINE / rs_protocol_init |
| rs_protocol_process_data           | rs_protocol_process                   |
| rs_protocol_reset_receive          | rs_protocol_reset                     |
| rs_protocol_build                  | rs_protocol_packet_build              |
| rs_protocol_build_safebuffer       | rs_protocol_packet_build_safebuffer   |
| rs_protocol_build_header           | rs_protocol_packet_build_header       |
| rs_protocol_add_packet_header      | rs_protocol_packet_add_header         |
| rs_protocol_build_single_param     | rs_protocol_packet_alloc_single       |
| rs_protocol_build_multiple_params  | rs_protocol_packet_alloc_multiple     |
| calculate_CRC16                    | rs_protocol_crc16                     |

The legacy callback does not get the instance: `void callback(safebuffer_t *sb, rsp_packet_type_t packet_type, void
*source)`. `rs_protocol_get_instance` returns the `struct rs_protocol` of an instance number, so legacy and new
functions can be mixed while code is moved over.

## Tests

The tests are in tests/rs_protocol_test. They run twice, with Zephyr's crc16_itu_t and with the lookup table, and check
that both give the CRC-16/XMODEM check value. Run them on an nRF52840 DK with tests/twister_ncs_2.9.0.bat and the COM
port of the board, or on native_sim on Linux.

This library has a dependency on safebuffer:

https://github.com/RobospaceNZ/safebuffer

rs_protocol V2.1.0 needs safebuffer V2.1.0 or newer, because both are Zephyr modules. rs_protocol V2.0.0 works with
safebuffer V1.0.2 and V2.0.0. Older versions of rs_protocol set `sb->p_gp`, which was removed in safebuffer V2.0.0, so
they only work with safebuffer V1.x.

The tests use the safebuffer cloned next to rs_protocol if there is one, otherwise the one in the west workspace. Pass
`-DSAFEBUFFER_DIR=<path>` (with twister `-x=SAFEBUFFER_DIR=<path>`) to use another copy.

## Changes in V2.1.0

- rs_protocol is now a Zephyr module, see [Import into Zephyr](#import-into-zephyr). Remove the `add_subdirectory`
  line from your CMakeLists.txt and the `rsource` line from your Kconfig file.
- `CONFIG_RS_PROTOCOL` is no longer enabled by default, set `CONFIG_RS_PROTOCOL=y` in prj.conf. It selects
  `CONFIG_SAFEBUFFER`.
- Needs safebuffer V2.1.0 or newer, which is also a Zephyr module. There are no changes to the code.

## Changes in V2.0.0

- New API with `struct rs_protocol` instances, defined with `RS_PROTOCOL_DEFINE` or `RS_PROTOCOL_DEFINE_STATIC_BUF`,
  or initialised with `rs_protocol_init`. The callback gets the instance, and `user_data` can be used for a context.
- Static receive buffers, no memory is allocated when packets are received.
- `rs_protocol_take_packet` keeps a received packet without copying it.
- After a header CRC, data CRC or length error the received bytes are processed again, so the next packet is not lost
  when a byte went missing.
- `CONFIG_RS_PROTOCOL_MAX_PACKET_SIZE` limits the size of packets received, it defaults to 4096. Empty packets are
  received as valid instead of a length error.
- The CRC is calculated with Zephyr's crc16_itu_t, which gives the same CRC as before. `CONFIG_CRC` is enabled
  automatically. Set `CONFIG_RS_PROTOCOL_CRC_TABLE=y` to use the lookup table.
- The build functions return -ENOMEM instead of building a truncated packet, and check the instance and the 16 bit
  length before allocating.
- The V1.x functions are kept while `CONFIG_RS_PROTOCOL_LEGACY_API` is enabled, which is the default. The default
  `CONFIG_RS_PROTOCOL_MAX_INSTANCES` is now 4.
- `sb->p_gp` is no longer set.

## Import into Zephyr

rs_protocol is a Zephyr module (see zephyr/module.yml), so Zephyr finds it by itself once it is in the west workspace or
listed in `ZEPHYR_EXTRA_MODULES`. No changes to CMakeLists.txt or Kconfig are needed, enable it in prj.conf:
```
CONFIG_RS_PROTOCOL=y
```

`CONFIG_RS_PROTOCOL` selects `CONFIG_SAFEBUFFER`, but safebuffer must also be added to the workspace or
`ZEPHYR_EXTRA_MODULES`, as shown below.

### Workspace application

If your application has its own west.yml (a workspace application, for example one started from Nordic's
ncs-example-application), add the library to that west.yml. Don't edit the west.yml of the SDK (nrf/west.yml), the
change is lost when the SDK is updated and is not part of your project.

Under remotes, add (once for all Robospace libraries):
```
    - name: robospace
      url-base: https://github.com/RobospaceNZ
```

Under projects, add:
```
    - name: rs_protocol
      remote: robospace
      revision: V2.1.0
      path: modules/lib/rs_protocol
    - name: safebuffer
      remote: robospace
      revision: V2.1.0
      path: modules/lib/safebuffer
```

Then run `west update` in the workspace folder.

### Freestanding application

If your application uses an SDK installed under C:\ncs, add the library to your application, for example as a git
submodule:
```
git submodule add https://github.com/RobospaceNZ/rs_protocol libs/rs_protocol
git submodule add https://github.com/RobospaceNZ/safebuffer libs/safebuffer
```

Add the following to your CMakeLists.txt file, before `find_package(Zephyr ...)`:
```
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/libs/rs_protocol)
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/libs/safebuffer)
```
