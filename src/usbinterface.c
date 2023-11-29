/* sd2snes - SD card based universal cartridge for the SNES
   Copyright (C) 2009-2010 Maximilian Rehkopf <otakon@gmx.net>
   AVR firmware portion

   Inspired by and based on code from sd2iec, written by Ingo Korb et al.
   See sdcard.c|h, config.h.

   FAT file system access based on code by ChaN, Jim Brain, Ingo Korb,
   see ff.c|h.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License only.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   usbinterface.c: usb packet interface handler
*/

#include <string.h>
#include <libgen.h>
#include <stdint.h>
#include <stdbool.h>
#include "bits.h"
#include "config.h"
#include "version.h"
#include "uart.h"
#include "snes.h"
#include "memory.h"
#include "msu1.h"
#include "fileops.h"
#include "ff.h"
#include "led.h"
#include "smc.h"
#include "timer.h"
#include "cli.h"
#include "fpga.h"
#include "fpga_spi.h"
#include "usbinterface.h"
#include "usbhw.h"
#include "rtc.h"
#include "cfg.h"
#include "cdcuser.h"
#include "cheat.h"

static inline void __DMB2(void) { asm volatile ("dmb" ::: "memory"); }

#define MAX_STRING_LENGTH 255

// Operations are composed of a request->response packet interface.
// Each packet it composed of Nx512B flits where N is 1 or more.
// Flits are composed of 8x64B Phits.
//
// Example USBINT_OP_GET opcode.
// client SEND CMD[USBINT_OP_GET]
// server RECV CMD[USBINT_OP_GET]
// server SEND RSP[USBINT_OP_GET]
// server SEND DAT[USBINT_OP_GET] [repeat]
// client RECV RSP[USBINT_OP_GET]
// client RECV DAT[USBINT_OP_GET] [repeat]
//
// NOTE: it may be beneficial to support command interleaving to reduce
// latency for push-style update operations from sd2snes

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

#define FOREACH_SERVER_STATE(OP)            \
  OP(USBINT_SERVER_STATE_IDLE)              \
                                            \
  OP(USBINT_SERVER_STATE_HANDLE_CMD)        \
  OP(USBINT_SERVER_STATE_HANDLE_DAT)        \
  OP(USBINT_SERVER_STATE_HANDLE_DATPUSH)    \
                                            \
  OP(USBINT_SERVER_STATE_HANDLE_REQDAT)     \
  OP(USBINT_SERVER_STATE_HANDLE_STREAM)     \
                                            \
  OP(USBINT_SERVER_STATE_HANDLE_LOCK)
enum usbint_server_state_e { FOREACH_SERVER_STATE(GENERATE_ENUM) };
#ifdef DEBUG_USB
static const char *usbint_server_state_s[] = { FOREACH_SERVER_STATE(GENERATE_STRING) };
#endif

// CLIENT mode unnecessary (replaced by a server operation)
#define FOREACH_CLIENT_STATE(OP)                \
  OP(USBINT_CLIENT_STATE_IDLE)                  \
                                                \
  OP(USBINT_CLIENT_STATE_HANDLE_CMD)            \
  OP(USBINT_CLIENT_STATE_HANDLE_DAT)
//enum usbint_client_state_e { FOREACH_CLIENT_STATE(GENERATE_ENUM) };
//static const char *usbint_client_state_s[] = { FOREACH_CLIENT_STATE(GENERATE_STRING) };

#define FOREACH_SERVER_STREAM_STATE(OP)     \
  OP(USBINT_SERVER_STREAM_STATE_IDLE)       \
                                            \
  OP(USBINT_SERVER_STREAM_STATE_INIT)       \
  OP(USBINT_SERVER_STREAM_STATE_ACTIVE)
enum usbint_server_stream_state_e { FOREACH_SERVER_STREAM_STATE(GENERATE_ENUM) };
//static const char *usbint_server_stream_state_s[] = { FOREACH_SERVER_STREAM_STATE(GENERATE_STRING) };

#define FOREACH_SERVER_OPCODE(OP)               \
  OP(USBINT_SERVER_OPCODE_GET)                  \
  OP(USBINT_SERVER_OPCODE_PUT)                  \
  OP(USBINT_SERVER_OPCODE_VGET)                 \
  OP(USBINT_SERVER_OPCODE_VPUT)                 \
                                                \
  OP(USBINT_SERVER_OPCODE_LS)                   \
  OP(USBINT_SERVER_OPCODE_MKDIR)                \
  OP(USBINT_SERVER_OPCODE_RM)                   \
  OP(USBINT_SERVER_OPCODE_MV)                   \
                                                \
  OP(USBINT_SERVER_OPCODE_RESET)                \
  OP(USBINT_SERVER_OPCODE_BOOT)                 \
  OP(USBINT_SERVER_OPCODE_POWER_CYCLE)          \
  OP(USBINT_SERVER_OPCODE_INFO)                 \
  OP(USBINT_SERVER_OPCODE_MENU_RESET)           \
  OP(USBINT_SERVER_OPCODE_STREAM)               \
  OP(USBINT_SERVER_OPCODE_TIME)                 \
                                                \
  OP(USBINT_SERVER_OPCODE_RESPONSE)             \
                                                \
  OP(USBINT_SERVER_OPCODE_SRAM_ENABLE)          \
  OP(USBINT_SERVER_OPCODE_SRAM_WRITE)           \
                                                \
  OP(USBINT_SERVER_OPCODE_IOVM_EXEC)            \
                                                \
  OP(USBINT_SERVER_OPCODE__COUNT)
enum usbint_server_opcode_e { FOREACH_SERVER_OPCODE(GENERATE_ENUM) };
#ifdef DEBUG_USB
static const char *usbint_server_opcode_s[] = { FOREACH_SERVER_OPCODE(GENERATE_STRING) };
#endif

#define FOREACH_SERVER_SPACE(OP)                \
  OP(USBINT_SERVER_SPACE_FILE)                  \
  OP(USBINT_SERVER_SPACE_SNES)                  \
  OP(USBINT_SERVER_SPACE_MSU)                   \
  OP(USBINT_SERVER_SPACE_CMD)                   \
  OP(USBINT_SERVER_SPACE_CONFIG)
enum usbint_server_space_e { FOREACH_SERVER_SPACE(GENERATE_ENUM) };
#ifdef DEBUG_USB
static const char *usbint_server_space_s[] = { FOREACH_SERVER_SPACE(GENERATE_STRING) };
#endif

#define FOREACH_SERVER_FLAGS(OP)               \
  OP(USBINT_SERVER_FLAGS_NONE=0)               \
  OP(USBINT_SERVER_FLAGS_SKIPRESET=1)          \
  OP(USBINT_SERVER_FLAGS_ONLYRESET=2)          \
  OP(USBINT_SERVER_FLAGS_CLRX=4)               \
  OP(USBINT_SERVER_FLAGS_SETX=8)               \
  OP(USBINT_SERVER_FLAGS_STREAMBURST=16)       \
  OP(USBINT_SERVER_FLAGS_SIZE_BIT9=32)         \
  OP(USBINT_SERVER_FLAGS_NORESP=64)            \
  OP(USBINT_SERVER_FLAGS_64BDATA=128)
enum usbint_server_flags_e { FOREACH_SERVER_FLAGS(GENERATE_ENUM) };
//static const char *usbint_server_flags_s[] = { FOREACH_SERVER_FLAGS(GENERATE_STRING) };

volatile enum usbint_server_state_e server_state = USBINT_SERVER_STATE_IDLE;
volatile enum usbint_server_stream_state_e stream_state;
static int reset_state = 0;
volatile static int cmdDat = 0;
volatile static unsigned connected = 0;

typedef uint32_t uint24_t;

enum iovm1_opcode {
    IOVM1_OPCODE_READ,
    IOVM1_OPCODE_WRITE,
    IOVM1_OPCODE_WAIT_UNTIL,
    IOVM1_OPCODE_ABORT_IF
};

enum iovm1_cmp_operator {
    IOVM1_CMP_EQ,
    IOVM1_CMP_NEQ,
    IOVM1_CMP_LT,
    IOVM1_CMP_NLT,
    IOVM1_CMP_GT,
    IOVM1_CMP_NGT
};

#define IOVM1_INST_OPCODE(x)        ((enum iovm1_opcode) ((x)&3))
#define IOVM1_INST_CMP_OPERATOR(x)  ((enum iovm1_cmp_operator) (((x)>>2)&7))

enum iovm1_memory_chip {
    MEM_SNES_WRAM,
    MEM_SNES_VRAM,
    MEM_SNES_CGRAM,
    MEM_SNES_OAM,
    MEM_SNES_ARAM,
    MEM_SNES_2C00,
    MEM_SNES_ROM,
    MEM_SNES_SRAM,
};

enum iovm1_state {
    IOVM1_STATE_EXECUTE_NEXT,
    IOVM1_STATE_ENDED,
    IOVM1_STATE_ERRORED,
};

enum iovm1_error {
    IOVM1_SUCCESS,
    IOVM1_ERROR_OUT_OF_RANGE,
    IOVM1_ERROR_INVALID_OPERATION_FOR_STATE,
    IOVM1_ERROR_UNKNOWN_OPCODE,
    IOVM1_ERROR_TIMED_OUT,
    IOVM1_ERROR_ABORTED,
    IOVM1_ERROR_MEMORY_CHIP_UNDEFINED,
    IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE,
    IOVM1_ERROR_MEMORY_CHIP_NOT_READABLE,
    IOVM1_ERROR_MEMORY_CHIP_NOT_WRITABLE,
};

static inline bool iovm1_memory_cmp(enum iovm1_cmp_operator q, uint8_t a, uint8_t b) {
    switch (q) {
        case IOVM1_CMP_EQ: return a == b;
        case IOVM1_CMP_NEQ: return a != b;
        case IOVM1_CMP_LT: return a < b;
        case IOVM1_CMP_NLT: return a >= b;
        case IOVM1_CMP_GT: return a > b;
        case IOVM1_CMP_NGT: return a <= b;
        default: return false;
    }
}

struct iovm1_t {
    // linear memory containing procedure instructions and immediate data
    struct {
        const uint8_t *ptr;
        uint32_t len;
        uint32_t off;
    } m;

    // current state
    enum iovm1_state s;
    enum iovm1_error e;

    // offset of current executing opcode:
    uint32_t p;

    // offset of next opcode:
    uint32_t pn;
};

struct iovm1_t vm;
uint8_t vm_procedure[512-8];

struct usbint_server_info_t {
  enum usbint_server_opcode_e opcode;
  enum usbint_server_space_e space;
  enum usbint_server_flags_e flags;

  uint32_t cmd_size;
  uint32_t block_size;
  uint32_t size;
  uint32_t total_size;
  uint32_t offset;

  // vector operations
  uint32_t vector_count;

  int vm_bytes_sent;

  uint8_t data_ready;
  int error;
};

volatile struct usbint_server_info_t server_info;
extern snes_romprops_t romprops;
extern uint8_t current_features;

unsigned recv_buffer_offset = 0;
unsigned char recv_buffer[USB_BLOCK_SIZE];
volatile unsigned char cmd_buffer[USB_BLOCK_SIZE];

// double buffered because send only guarantees that a transfer is
// volatile since CDC needs to send it
volatile uint8_t send_buffer_index = 0;
volatile unsigned char send_buffer[2][USB_BLOCK_SIZE];

// directory
static DIR     dh;
static FILINFO fi;
static int     fiCont = 0;
static FIL     fh;
static char    fbuf[MAX_STRING_LENGTH + 1];

extern cfg_t CFG;

// reset
void usbint_set_state(unsigned open) {
    connected = open;
}

// TODO: New Design
// - Unify interrupt handler and RAM/FILE IO
// - Add IRQ disable/enable to other code to protect against conflict
// - Need dedicated file pointer since it is retained across interrupts.
// - Figure out which operation still need to be part of the main loop (boot, reset, etc).
// - Support multiple commands in IO commands in flight.
// - Separate input/output USB IRQ disable.

// collect a flit
void usbint_recv_flit(const unsigned char *in, int length) {
    //if (!length) return;

    // read in new flit
    unsigned bytesRead = min(length, (!cmdDat ? USB_BLOCK_SIZE : server_info.block_size) - recv_buffer_offset);
    memcpy(recv_buffer + recv_buffer_offset, in, bytesRead);
    unsigned old_recv_buffer_offset = recv_buffer_offset;
    recv_buffer_offset += bytesRead;

    //PRINT_MSG("[ flt]");
    //printf(" l: %d ", length);
    //PRINT_END();

    if (!cmdDat) {
        // FIXME: make this more general.  Commands should be under 64B
        // check the command type for 64B vs 512B
        if (recv_buffer_offset < 64) {
            // make sure we don't accidentally accept a command that isn't ready.
            server_info.cmd_size = USB_BLOCK_SIZE;
        }
        else if (old_recv_buffer_offset < 64 && 64 <= recv_buffer_offset) {
            server_info.cmd_size = (recv_buffer[4] == USBINT_SERVER_OPCODE_VGET || recv_buffer[4] == USBINT_SERVER_OPCODE_IOVM_EXEC || recv_buffer[4] == USBINT_SERVER_OPCODE_VPUT) ? 64 : 512;
        }
    }

    unsigned size = (!cmdDat ? server_info.cmd_size : server_info.block_size);
    if (recv_buffer_offset >= size) {
        unsigned cmdDat_old = cmdDat;
        if (!cmdDat) {
            server_info.block_size = (recv_buffer[6] & USBINT_SERVER_FLAGS_64BDATA) ? 64 : USB_BLOCK_SIZE;
            // copy the command to its buffer
            memcpy((unsigned char*)cmd_buffer, recv_buffer, size);
            //__DMB2();
        }
        //printf(" cmdDat: %d cmd_size: %d block_size: %d", cmdDat, (int)server_info.cmd_size, (int)server_info.block_size);
        usbint_recv_block();

        // There's a race with NORESP where the data can show up before we have setup the handler.  If it does this then
        // the old code would skip receiving the flit and it would hang because the interrupt handler wouldn't be called again
        // To avoid that we disable the handler here and let the menu loop re-enable it when we have it locked.
        if (!cmdDat_old && cmdDat) USB_DisableIRQ();

        // FIXME: implement proper circular queue.

        // shift extra bytes down
        memmove((unsigned char*)recv_buffer, recv_buffer + size, recv_buffer_offset - size);
        recv_buffer_offset -= size;

        // copy any remaining input bytes
        memcpy((unsigned char*)recv_buffer + recv_buffer_offset, in + bytesRead, length - bytesRead);
        recv_buffer_offset += length - bytesRead;
    }
}

void usbint_recv_block(void) {
    static uint32_t count = 0;

    // check header
    if (!cmdDat) {
        // command operations
        //PRINT_MSG("[ cmd]");

        if (cmd_buffer[0] == 'U' && cmd_buffer[1] == 'S' && cmd_buffer[2] == 'B' && cmd_buffer[3] == 'A') {
            if (cmd_buffer[4] == USBINT_SERVER_OPCODE_PUT || cmd_buffer[4] == USBINT_SERVER_OPCODE_VPUT) {
                // put operations require
                cmdDat = 1;
            }
            //PRINT_FUNCTION();
            //PRINT_MSG("[ cmd]");

            //PRINT_STATE(server_state);
            server_state = USBINT_SERVER_STATE_HANDLE_CMD;
            //PRINT_STATE(server_state);

            //PRINT_CMD(cmd_buffer);
            //PRINT_END();
        }
    }
    else {
        // data operations
        // for USBINT_SERVER_OPCODE_PUT, USBINT_SERVER_OPCODE_VPUT

        if (server_info.space == USBINT_SERVER_SPACE_FILE) {
            UINT bytesRecv = 0;
            server_info.error |= f_lseek(&fh, count);
            do {
                UINT bytesWritten = 0;
                UINT remainingBytes = min(server_info.block_size - bytesRecv, server_info.size - count);
                //UINT remainingBytes = server_info.block_size - bytesRecv;
                server_info.error |= f_write(&fh, recv_buffer + bytesRecv, remainingBytes, &bytesWritten);
                bytesRecv += bytesWritten;
                //server_info.offset += bytesWritten;
                count += bytesWritten;
            } while (bytesRecv != server_info.block_size && count < server_info.size);
        }
        else {
            // write SRAM or CONFIG
            UINT blockBytesWritten = 0;

            //PRINT_MSG("[ dat]");
            do {
                UINT bytesWritten = 0;
                if (server_info.space == USBINT_SERVER_SPACE_SNES) {
                    UINT remainingBytes = min(server_info.block_size - blockBytesWritten, server_info.size - count);
                    bytesWritten = sram_writeblock(recv_buffer + blockBytesWritten, server_info.offset + count, remainingBytes);
                }
                else if (server_info.space == USBINT_SERVER_SPACE_CMD) {
                    UINT remainingBytes = min(server_info.block_size - blockBytesWritten, server_info.size - count);
                    bytesWritten = snescmd_writeblock(recv_buffer + blockBytesWritten, server_info.offset + count, remainingBytes);
                }
                else {
                    uint8_t group = server_info.size & 0xFF;
                    uint8_t index = server_info.offset & 0xFF;
                    uint8_t data = (server_info.offset >> 8) & 0xFF;
                    uint8_t invmask = (server_info.offset >> 16) & 0xFF;
                    fpga_write_config(group, index, data, invmask);
                    bytesWritten = 1;
                    server_info.size = 1; // reset size/group-valid field
                }
                blockBytesWritten += bytesWritten;
                count += bytesWritten;

                // generate next offset and size
                if (server_info.opcode == USBINT_SERVER_OPCODE_VPUT && count == server_info.size) {
                    while (server_info.vector_count < 8) {
                        server_info.vector_count++;
                        //PRINT_MSG("[ next]");

                        if (cmd_buffer[32 + server_info.vector_count * 4]) {
                            server_info.size = cmd_buffer[32 + server_info.vector_count * 4];

                            server_info.offset  = 0;
                            server_info.offset |= cmd_buffer[33 + server_info.vector_count * 4]; server_info.offset <<= 8;
                            server_info.offset |= cmd_buffer[34 + server_info.vector_count * 4]; server_info.offset <<= 8;
                            server_info.offset |= cmd_buffer[35 + server_info.vector_count * 4]; server_info.offset <<= 0;

                            count = 0;
                            break;
                        }
                    }
                }
            } while (blockBytesWritten != server_info.block_size && count < server_info.size);
            // FIXME: figure out how to copy recv_buffer somewhere
            //count += USB_BLOCK_SIZE;
        }

        if (count >= server_info.size) {
            if (server_info.space == USBINT_SERVER_SPACE_FILE) {
                f_close(&fh);
            }
            //PRINT_FUNCTION();
            //PRINT_MSG("[ datDone]");

            server_info.cmd_size = USB_BLOCK_SIZE;
            server_info.block_size = USB_BLOCK_SIZE;
            cmdDat = 0;
            count = 0;

            // unlock any sram transfer lock
            //PRINT_STATE(server_state);
            if (server_state == USBINT_SERVER_STATE_HANDLE_LOCK) {
                // disable interrupts again to let the command loop finish
                USB_DisableIRQ();
                server_state = USBINT_SERVER_STATE_IDLE;
            }
            //PRINT_STATE(server_state);

            //PRINT_DAT((int)count, (int)server_info.size);

            //PRINT_END();
        }

   }

}

// send a block
void usbint_send_block(int blockSize) {
    // FIXME: don't need to double buffer anymore if using interrupt
    while(CDC_block_send((unsigned char*)send_buffer[send_buffer_index], blockSize) == -1) { usbint_check_connect(); }
    send_buffer_index = (send_buffer_index + 1) & 0x1;
}

int usbint_server_busy() {
    // LCK isn't considered busy
    // FIXME: stream locks up connection until disconnect
    return server_state == USBINT_SERVER_STATE_HANDLE_CMD || server_state == USBINT_SERVER_STATE_HANDLE_DAT || server_state == USBINT_SERVER_STATE_HANDLE_DATPUSH || server_state == USBINT_SERVER_STATE_HANDLE_STREAM;
}

int usbint_server_dat() {
    // LCK isn't considered busy
    return server_state == USBINT_SERVER_STATE_HANDLE_DAT || server_state == USBINT_SERVER_STATE_HANDLE_STREAM;
}

int usbint_server_reset() { return reset_state; }

void usbint_check_connect(void) {
    static unsigned connected_prev = 0;

    if (connected_prev ^ connected) {
        if (!connected) {
            server_state = USBINT_SERVER_STATE_IDLE;
            server_info.data_ready = 0;
            cmdDat = 0;
        }
        //set_usb_status(connected ? USB_SNES_STATUS_SET_CONNECTED : USB_SNES_STATUS_CLR_CONNECTED);

        PRINT_FUNCTION();
        PRINT_MSG(connected ? "[open]" : "[clos]");
        PRINT_END();

        connected_prev = connected;
    }
}

// top level state machine
int usbint_handler(void) {
    int ret = 0;

    usbint_check_connect();

    switch(server_state) {
            case USBINT_SERVER_STATE_HANDLE_CMD: ret = usbint_handler_cmd(); break;
            // FIXME: are these needed anymore?  PUSHDAT was for non-interrupt operation and EXE uses flags now
            case USBINT_SERVER_STATE_HANDLE_DATPUSH: ret = usbint_handler_dat(); break;

            default: break;
    }

    return ret;
}

int usbint_handler_cmd(void) {
    int ret = 0;
    uint8_t *fileName = (uint8_t *)cmd_buffer + 256;

    PRINT_FUNCTION();
    PRINT_MSG("[hcmd]");

    // decode command
    server_info.opcode = cmd_buffer[4];
    server_info.space = cmd_buffer[5];
    server_info.flags = cmd_buffer[6];

    server_info.size  = cmd_buffer[252]; server_info.size <<= 8;
    server_info.size |= cmd_buffer[253]; server_info.size <<= 8;
    server_info.size |= cmd_buffer[254]; server_info.size <<= 8;
    server_info.size |= cmd_buffer[255]; server_info.size <<= 0;

    server_info.total_size = server_info.size;

    server_info.offset = 0;
    server_info.error = 0;

    memset((unsigned char *)send_buffer[send_buffer_index], 0, USB_BLOCK_SIZE);

    switch (server_info.opcode) {
    case USBINT_SERVER_OPCODE_GET: {
        if (server_info.space == USBINT_SERVER_SPACE_FILE) {
            fi.lfname = fbuf;
            fi.lfsize = MAX_STRING_LENGTH;
            server_info.error |= f_stat((TCHAR*)fileName, &fi);
            server_info.size = fi.fsize;
            server_info.total_size = server_info.size;
            server_info.error |= f_open(&fh, (TCHAR*)fileName, FA_READ);
        }
        else {
            server_info.offset  = cmd_buffer[256]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[257]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[258]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[259]; server_info.offset <<= 0;
        }
        break;
    }
    case USBINT_SERVER_OPCODE_PUT: {
        if (server_info.space == USBINT_SERVER_SPACE_FILE) {
            // file
            server_info.error = f_open(&fh, (TCHAR*)fileName, FA_WRITE | FA_CREATE_ALWAYS);
        }
        else {
            server_info.offset  = cmd_buffer[256]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[257]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[258]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[259]; server_info.offset <<= 0;
        }
        break;
    }
    case USBINT_SERVER_OPCODE_SRAM_ENABLE:
        // enables/disables periodic SRAM writing to SD card:
        snes_enable_sram_write(cmd_buffer[7] != 0);
        break;
    case USBINT_SERVER_OPCODE_SRAM_WRITE:
        // immediately writes SRAM contents to SD card:
        snes_do_sram_write();
        break;
    case USBINT_SERVER_OPCODE_IOVM_EXEC: {
        // TODO: turn this into a PUT-like opcode to accept large-ish programs
        // accepts either 64-byte or 512-byte requests
        // always resets block_size to 64 for responses
        server_info.size = 0;
        server_info.total_size = 0;

        // make sure we can reply with an error:
        server_info.flags &= USBINT_SERVER_FLAGS_NORESP;

        // determine 9-bit length of IOVM program:
        unsigned len = cmd_buffer[7];
        if (server_info.flags & USBINT_SERVER_FLAGS_SIZE_BIT9) {
            len |= 0x100;
        }
        // validate length:
        if (len > server_info.block_size - 8) {
            server_info.error = 128;
            break;
        }

        // use 64-byte response block size for lower latency:
        server_info.block_size = 64;

        // copy procedure from command buffer to vm_procedure:
        memcpy(vm_procedure, (const uint8_t *) cmd_buffer + 8, len);

        // initialize vm:
        vm.m.ptr = vm_procedure;
        vm.m.len = len;
        vm.m.off = 0;
        vm.pn = 0;
        vm.p = 0;
        vm.e = IOVM1_SUCCESS;
        vm.s = IOVM1_STATE_EXECUTE_NEXT;

        // don't know how much data up-front will be returned, so just use 1:
        server_info.size = 1;
        server_info.total_size = server_info.size;

        // disable first response block until iovm sends data or ends:
        server_info.flags |= USBINT_SERVER_FLAGS_NORESP;

        break;
    }
    case USBINT_SERVER_OPCODE_VGET:
    case USBINT_SERVER_OPCODE_VPUT: {
        // don't support MSU for now
        server_info.error = (server_info.space == USBINT_SERVER_SPACE_FILE);

        if (!server_info.error) {
            // get total size
            server_info.total_size = 0;

            for (unsigned i = 0; i < 8; i++) {
                server_info.total_size += cmd_buffer[32 + i * 4];
            }

            server_info.vector_count = 0;

            // load first offset and size
            server_info.size = cmd_buffer[32 + server_info.vector_count * 4];

            server_info.offset  = 0;
            server_info.offset |= cmd_buffer[33 + server_info.vector_count * 4]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[34 + server_info.vector_count * 4]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[35 + server_info.vector_count * 4]; server_info.offset <<= 0;

            //for (unsigned i = 0; i < 8; i++) {
            //    unsigned offset = 0;
            //    offset |= cmd_buffer[33 + i * 4]; offset <<= 8;
            //    offset |= cmd_buffer[34 + i * 4]; offset <<= 8;
            //    offset |= cmd_buffer[35 + i * 4]; offset <<= 0;
            //    unsigned size = cmd_buffer[32 + i * 4];
            //    printf("(%i: %06x, %02x) ", i, offset, size);
            //}

            //uint8_t group = server_info.size & 0xFF;
            //uint8_t index = server_info.offset & 0xFF;
            //uint8_t data = (server_info.offset >> 8) & 0xFF;
            //uint8_t invmask = (server_info.offset >> 16) & 0xFF;
            //printf(" [CONFIG] %2x %2x %2x %2x ", group, index, data, invmask);

        }

        break;
    }
    case USBINT_SERVER_OPCODE_LS: {
        fiCont = 0;
        fi.lfname = fbuf;
        fi.lfsize = MAX_STRING_LENGTH;
        server_info.error |= f_opendir(&dh, (TCHAR *)fileName) != FR_OK;
        server_info.size = 1;
        server_info.total_size = server_info.size;
        break;
    }
    case USBINT_SERVER_OPCODE_MKDIR: {
        server_info.error |= f_mkdir((TCHAR *)fileName) != FR_OK;
        break;
    }
    case USBINT_SERVER_OPCODE_RM: {
        server_info.error |= f_unlink((TCHAR *)fileName) != FR_OK;
        break;
    }
    case USBINT_SERVER_OPCODE_RESET: {
        ret = SNES_CMD_RESET;
        break;
    }
    case USBINT_SERVER_OPCODE_MENU_RESET: {
        ret = SNES_CMD_RESET_TO_MENU;
        break;
    }
    case USBINT_SERVER_OPCODE_TIME: {
        struct tm time;

        // FIXME: figure out where we want to store this data
        time.tm_sec = (uint8_t) cmd_buffer[4+4];
        time.tm_min = (uint8_t) cmd_buffer[5+4];
        time.tm_hour = (uint8_t) cmd_buffer[6+4];
        time.tm_mday = (uint8_t) cmd_buffer[7+4];
        time.tm_mon = (uint8_t) cmd_buffer[8+4];
        time.tm_year = (uint16_t) ((cmd_buffer[9+4] << 8) + cmd_buffer[10+4]);
        time.tm_wday = (uint8_t) cmd_buffer[11+4];

        set_rtc(&time);
    }
    case USBINT_SERVER_OPCODE_MV: {
        // copy string name
        strncpy((TCHAR *)fbuf, (TCHAR *)fileName, MAX_STRING_LENGTH + 1);
        char *newFileName = fbuf;
        // remove the basename
        if ((newFileName = strrchr(newFileName, '/'))) *(newFileName + 1) = '\0';
        newFileName = fbuf;
        // add the new basename
        strncat((TCHAR *)newFileName, (TCHAR *)cmd_buffer + 8, MAX_STRING_LENGTH - 8 - strlen(fbuf));
        // perform move
        server_info.error |= f_rename((TCHAR *)fileName, (TCHAR *)newFileName) != FR_OK;
        break;
    }
    case USBINT_SERVER_OPCODE_STREAM: {
        // this is a special opcode that must point to the MSU space for streaming writes
        server_info.error = server_info.space != USBINT_SERVER_SPACE_MSU;

        if (!server_info.error) {
            stream_state = USBINT_SERVER_STREAM_STATE_INIT;

            server_info.offset  = cmd_buffer[256]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[257]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[258]; server_info.offset <<= 8;
            server_info.offset |= cmd_buffer[259]; server_info.offset <<= 0;
        }
        break;
    }
    default: // unrecognized
        server_info.error = 1;
    case USBINT_SERVER_OPCODE_INFO:
    case USBINT_SERVER_OPCODE_BOOT:
    case USBINT_SERVER_OPCODE_POWER_CYCLE:
        // nop
        break;
    }

    // clear the execution cheats
    if (!server_info.error && (server_info.flags & USBINT_SERVER_FLAGS_CLRX)) {
        fpga_set_snescmd_addr(SNESCMD_WRAM_CHEATS);
        fpga_write_snescmd(ASM_RTS);

        // FIXME: this is a hack.  add a proper spinloop with status bit
        // wait to make sure we are out of the code.  one frame should do
        // could add a data region and wait for the write
        sleep_ms(16);
    }

    // boot the ROM
    if (server_info.opcode == USBINT_SERVER_OPCODE_BOOT) {
        // manually control reset in case we want to patch
        if (!(server_info.flags & USBINT_SERVER_FLAGS_ONLYRESET)) {
            strncpy ((char *)file_lfn, (char *)fileName, 256);
            cfg_add_last_game(file_lfn);
            // assert reset before loading
            assert_reset();
            // there may not be a menu to interact with so don't wait for SNES
            load_rom(file_lfn, 0, LOADROM_WITH_SRAM | LOADROM_WITH_FPGA /*| LOADROM_WAIT_SNES*/);
            //assert_reset();
            init(file_lfn);
            reset_state = 1;
        }

        if (!(server_info.flags & USBINT_SERVER_FLAGS_SKIPRESET)) {
            deassert_reset();
            // enter the game loop like the menu would
            ret = SNES_CMD_GAMELOOP;
            reset_state = 0;
        }
    }

    PRINT_STATE(server_state);

    // decide next state
    if (server_info.opcode == USBINT_SERVER_OPCODE_GET || server_info.opcode == USBINT_SERVER_OPCODE_VGET || server_info.opcode == USBINT_SERVER_OPCODE_IOVM_EXEC || server_info.opcode == USBINT_SERVER_OPCODE_LS) {
        // we lock on data transfers so use interrupt for everything
        server_state = USBINT_SERVER_STATE_HANDLE_DAT;
    }
    else if (server_info.opcode == USBINT_SERVER_OPCODE_PUT || server_info.opcode == USBINT_SERVER_OPCODE_VPUT) {
        server_state = USBINT_SERVER_STATE_HANDLE_LOCK;
    }
    else if (server_info.opcode == USBINT_SERVER_OPCODE_STREAM) {
        server_state = USBINT_SERVER_STATE_HANDLE_STREAM;
    }
    else {
        server_state = USBINT_SERVER_STATE_IDLE;
    }
    PRINT_STATE(server_state);

    PRINT_CMD(cmd_buffer);

    if (server_info.opcode == USBINT_SERVER_OPCODE_BOOT) {
        printf("Boot name: %s ", (char *)file_lfn);
    }

    PRINT_END();

    // create response
    send_buffer[send_buffer_index][0] = 'U';
    send_buffer[send_buffer_index][1] = 'S';
    send_buffer[send_buffer_index][2] = 'B';
    send_buffer[send_buffer_index][3] = 'A';
    // opcode
    send_buffer[send_buffer_index][4] = USBINT_SERVER_OPCODE_RESPONSE;
    // error
    send_buffer[send_buffer_index][5] = server_info.error;
    // size
    send_buffer[send_buffer_index][252] = (server_info.total_size >> 24) & 0xFF;
    send_buffer[send_buffer_index][253] = (server_info.total_size >> 16) & 0xFF;
    send_buffer[send_buffer_index][254] = (server_info.total_size >>  8) & 0xFF;
    send_buffer[send_buffer_index][255] = (server_info.total_size >>  0) & 0xFF;

    if (server_info.opcode == USBINT_SERVER_OPCODE_INFO) {
        send_buffer[send_buffer_index][256] = (CONFIG_FWVER >> 24) & 0xFF;
        send_buffer[send_buffer_index][257] = (CONFIG_FWVER >> 16) & 0xFF;
        send_buffer[send_buffer_index][258] = (CONFIG_FWVER >>  8) & 0xFF;
        send_buffer[send_buffer_index][259] = (CONFIG_FWVER >>  0) & 0xFF;
        strncpy((char *)(send_buffer[send_buffer_index]) + 256 +  4, CONFIG_VERSION, 64);
        strncpy((char *)(send_buffer[send_buffer_index]) + 260 + 64, DEVICE_NAME, 64);

        // features
        send_buffer[send_buffer_index][6] = current_features;
        // leave room for more feature flags at [7]
        // supports this many newer opcodes than RESPONSE:
        send_buffer[send_buffer_index][8] = USBINT_SERVER_OPCODE__COUNT - (USBINT_SERVER_OPCODE_RESPONSE + 1);
        // currently executing ROM
        char *tempFileName = current_filename;
        // chop from the beginning
        if (strlen(tempFileName) > (MAX_STRING_LENGTH - 16)) tempFileName += strlen(tempFileName) - (MAX_STRING_LENGTH - 16);
        strncpy((char *)(send_buffer[send_buffer_index]) + 16, current_filename, MAX_STRING_LENGTH - 16);
    }

    // send response.  also triggers data interrupt.
    server_info.data_ready = (server_state == USBINT_SERVER_STATE_HANDLE_DAT) || (server_state == USBINT_SERVER_STATE_HANDLE_STREAM);
    //__DMB2();
    DBG_USBHW printf("send_block: \n");
    DBG_USBHW uart_trace((void*)send_buffer[send_buffer_index], 0, USB_BLOCK_SIZE);
    if (!(server_info.flags & USBINT_SERVER_FLAGS_NORESP)) {
        usbint_send_block(USB_BLOCK_SIZE);
    }
    // NOTE: STREAM should accept the response to avoid the hack below
    else if (server_state == USBINT_SERVER_STATE_HANDLE_DAT) {
        // send the first data beat to trigger the interrupt
        server_state = USBINT_SERVER_STATE_HANDLE_DATPUSH;
        usbint_handler_dat();
        if (server_state == USBINT_SERVER_STATE_HANDLE_DATPUSH) server_state = USBINT_SERVER_STATE_HANDLE_DAT;
    }

    int dataWait = 0;
    if (server_info.opcode == USBINT_SERVER_OPCODE_PUT || server_info.opcode == USBINT_SERVER_OPCODE_VPUT) {
        // allow the data to come in
        dataWait = 1;
        USB_EnableIRQ();
    }

    // lock process.  this avoids a conflict with the rest of the menu accessing the file system or sram
    // FIXME: streaming blocks saves
    while(server_state == USBINT_SERVER_STATE_HANDLE_LOCK || server_state == USBINT_SERVER_STATE_HANDLE_DAT || server_state == USBINT_SERVER_STATE_HANDLE_STREAM) { usbint_check_connect(); };

    // if the execute bit is set then perform operation
    if (server_info.flags & USBINT_SERVER_FLAGS_SETX) {
        usbint_handler_exe();
    }

    // allow next command to come after prior data
    if (dataWait) USB_EnableIRQ();

    if (server_info.opcode == USBINT_SERVER_OPCODE_POWER_CYCLE) {
        NVIC_SystemReset();
    }

    return ret;
}

static uint24_t snescmd_addr_from_chip(enum iovm1_memory_chip c, uint24_t a, int l, uint24_t *addr) {
    // special case for 2C00 EXE buffer:
    if (a >= 0x200) {
        return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
    }
    if (a + l > 0x200) {
        return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
    }

    *addr = 0x2C00 + a;

    return IOVM1_SUCCESS;
}

static uint24_t sram_addr_from_chip(enum iovm1_memory_chip c, uint24_t a, int l, uint24_t *addr) {
    switch (c) {
        case MEM_SNES_WRAM: // WRAM:
            if (a >= 0x20000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x20000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xF50000 + a;
            break;
        case MEM_SNES_VRAM: // VRAM:
            if (a >= 0x10000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x10000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xF70000 + a;
            break;
        case MEM_SNES_CGRAM: // CGRAM:
            if (a >= 0x200) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x200) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xF90000 + a;
            break;
        case MEM_SNES_OAM: // OAM:
            if (a >= 0x220) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x220) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xF90200 + a;
            break;
        case MEM_SNES_ARAM: // APURAM:
            if (a >= 0x10000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x10000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xF80000 + a;
            break;
        case MEM_SNES_ROM: // ROM:
            if (a >= 0xE00000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0xE00000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0x000000 + a;
            break;
        case MEM_SNES_SRAM: // SRAM:
            if (a >= 0x150000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            if (a + l > 0x150000) {
                return IOVM1_ERROR_MEMORY_CHIP_ADDRESS_OUT_OF_RANGE;
            }
            *addr = 0xE00000 + a;
            break;
        default: // memory chip not defined:
            return IOVM1_ERROR_MEMORY_CHIP_UNDEFINED;
    }

    return IOVM1_SUCCESS;
}

static enum iovm1_error memory_chip_is_writable(enum iovm1_memory_chip c, uint24_t a) {
    switch (c) {
        case MEM_SNES_WRAM: // WRAM:
        case MEM_SNES_VRAM: // VRAM:
        case MEM_SNES_CGRAM: // CGRAM:
        case MEM_SNES_OAM: // OAM:
        case MEM_SNES_ARAM: // APURAM:
            return IOVM1_ERROR_MEMORY_CHIP_NOT_WRITABLE;
        case MEM_SNES_2C00:
        case MEM_SNES_ROM: // ROM:
        case MEM_SNES_SRAM: // SRAM:
            return IOVM1_SUCCESS;
        default: // memory chip not defined:
            return IOVM1_ERROR_MEMORY_CHIP_UNDEFINED;
    }
}

static void send_msg_byte(uint8_t b) {
    send_buffer[send_buffer_index][server_info.vm_bytes_sent++] = b;

    if (server_info.vm_bytes_sent >= server_info.block_size) {
        // flush buffer to USB:
        usbint_send_block(server_info.block_size);
        server_info.vm_bytes_sent = 0;
    }
}

// send a program-end message to the client
static void send_end_msg(void) {
    // end program message:
    send_msg_byte(0xFF);
    // error code:
    send_msg_byte(vm.e);
    // offset within program of where we ended:
    send_msg_byte(vm.p & 0xFF);
    send_msg_byte((vm.p >> 8) & 0xFF);
}

// executes the next IOVM instruction
static inline enum iovm1_error iovm1_exec(void) {
    /*
IOVM1 instruction byte format:

   765432 10
  [?????? oo]

    o = opcode              [0..3]
    ? = varies by opcode

opcodes (o):
-----------------------
  0=READ:               reads bytes from memory chip
     765432 10
    [------ 00]

        enum iovm1_memory_chip c;
        uint24_t a;
        uint8_t l_raw;
        int l;

        // memory chip identifier (0..255)
        c  = m[p++];
        // memory address in 24-bit little-endian byte order:
        a  = m[p++];
        a |= m[p++] << 8;
        a |= m[p++] << 16;
        // length of read in bytes (treat 0 as 256, else 1..255)
        l_raw = m[p++];
        l = translate_zero_byte(vm->rd.l_raw);

-----------------------
  1=WRITE:              writes bytes to memory chip
     765432 10
    [------ 01]

        enum iovm1_memory_chip c;
        uint24_t a;
        uint8_t l_raw;
        int l;

        // memory chip identifier (0..255)
        c  = m[p++]
        // memory address in 24-bit little-endian byte order:
        a  = m[p++]
        a |= m[p++] << 8
        a |= m[p++] << 16
        // length of write in bytes (treat 0 as 256, else 1..255)
        l_raw = m[p++]
        l  = translate_zero_byte(l_raw)

-----------------------
  2=WAIT_UNTIL:         waits until a byte read from a memory chip compares to a value -- for read/write timing purposes
     765 432 10
    [--- qqq 10]
        q = comparison operator [0..7]
            0 =        EQ; equals
            1 =       NEQ; not equals
            2 =        LT; less than
            3 =       NLT; not less than
            4 =        GT; greater than
            5 =       NGT; not greater than
            6 = undefined; returns false
            7 = undefined; returns false

        enum iovm1_memory_chip c;
        uint24_t a;
        uint8_t v;
        uint8_t k;

        // memory chip identifier (0..255)
        c  = m[p++]
        // memory address in 24-bit little-endian byte order:
        a  = m[p++]
        a |= m[p++] << 8
        a |= m[p++] << 16
        // comparison byte
        v  = m[p++]
        // comparison mask
        k  = m[p++]

-----------------------
  3=ABORT_IF:           reads a byte from a memory chip and compares to a value; if true, aborts program execution
     765 432 10
    [--- qqq 11]
        q = comparison operator [0..7]
            0 =        EQ; equals
            1 =       NEQ; not equals
            2 =        LT; less than
            3 =       NLT; not less than
            4 =        GT; greater than
            5 =       NGT; not greater than
            6 = undefined; returns false
            7 = undefined; returns false

        enum iovm1_memory_chip c;
        uint24_t a;
        uint8_t v;
        uint8_t k;

        // memory chip identifier (0..255)
        c  = m[p++]
        // memory address in 24-bit little-endian byte order:
        a  = m[p++]
        a |= m[p++] << 8
        a |= m[p++] << 16
        // comparison byte
        v  = m[p++]
        // comparison mask
        k  = m[p++]
    */

    // buffer for data to read into:
    uint8_t rdbuf[256 + 6], *d;
    uint24_t addr;

    // first check here to handle read/write/wait instructions -- for lower latency between loop iterations:
    if (vm.s == IOVM1_STATE_ERRORED) {
        // maintain errored state until explicit reset:
        return vm.e;
    }

    while (vm.s == IOVM1_STATE_EXECUTE_NEXT) {
        vm.m.off = vm.pn;
        vm.p = vm.m.off;

        if (vm.m.off >= vm.m.len) {
            vm.s = IOVM1_STATE_ENDED;
            vm.e = IOVM1_SUCCESS;
            send_end_msg();
            return vm.e;
        }

        // read instruction byte:
        uint8_t x = vm.m.ptr[vm.m.off++];

        // instruction opcode:
        uint8_t o = IOVM1_INST_OPCODE(x);
        switch (o) {
            case IOVM1_OPCODE_READ: {
                vm.pn = vm.m.off + 5;

                // memory chip identifier:
                uint8_t c = (enum iovm1_memory_chip)vm.m.ptr[vm.m.off++];
                // 24-bit address:
                uint24_t lo = (uint24_t)(vm.m.ptr[vm.m.off++]);
                uint24_t hi = (uint24_t)(vm.m.ptr[vm.m.off++]) << 8;
                uint24_t bk = (uint24_t)(vm.m.ptr[vm.m.off++]) << 16;
                uint24_t a = bk | hi | lo;
                // length of read in bytes:
                uint8_t l_raw = vm.m.ptr[vm.m.off++];
                // translate 0 -> 256:
                int l = l_raw;
                if (l == 0) { l = 256; }

                // NOTE: we buffer the read data into memory first so that we don't have to wait for a split USB packet to go out
                // which may compromise the user's timing requirements of the read operation.

                d = rdbuf;
                if (c == MEM_SNES_2C00) {
                    vm.e = snescmd_addr_from_chip(c, a, l, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    // start read-data message:
                    *d++ = 0xFE;
                    // memory chip:
                    *d++ = (c);
                    // 24-bit address:
                    *d++ = (a & 0xFF);
                    *d++ = ((a >> 8) & 0xFF);
                    *d++ = ((a >> 16) & 0xFF);
                    // length of read (1..255 bytes, and 0 encodes 256 bytes):
                    *d++ = l_raw;

                    fpga_set_snescmd_addr(addr);
                    while (l-- > 0) {
                        *d++ = fpga_read_snescmd();
                    }
                } else {
                    vm.e = sram_addr_from_chip(c, a, l, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    // start read-data message:
                    *d++ = (0xFE);
                    // memory chip:
                    *d++ = (c);
                    // 24-bit address:
                    *d++ = (a & 0xFF);
                    *d++ = ((a >> 8) & 0xFF);
                    *d++ = ((a >> 16) & 0xFF);
                    // length of read (1..255 bytes, and 0 encodes 256 bytes):
                    *d++ = l_raw;

                    set_mcu_addr(addr);
                    FPGA_SELECT();
                    FPGA_TX_BYTE(0x88);   /* READ */
                    while (l-- > 0) {
                        FPGA_WAIT_RDY();
                        *d++ = FPGA_RX_BYTE();
                    }
                    FPGA_DESELECT();
                }

                // send out buffered read data:
                for (uint8_t *s = rdbuf; s < d; s++) {
                    send_msg_byte(*s);
                }

                // start next instruction:
                vm.e = IOVM1_SUCCESS;
                return vm.e;
            }
            case IOVM1_OPCODE_WRITE: {
                vm.pn = vm.m.off + 5;

                // memory chip identifier:
                uint8_t c = (enum iovm1_memory_chip)vm.m.ptr[vm.m.off++];
                // 24-bit address:
                uint24_t lo = (uint24_t)(vm.m.ptr[vm.m.off++]);
                uint24_t hi = (uint24_t)(vm.m.ptr[vm.m.off++]) << 8;
                uint24_t bk = (uint24_t)(vm.m.ptr[vm.m.off++]) << 16;
                uint24_t a = bk | hi | lo;

                // length of read in bytes:
                uint8_t l_raw = vm.m.ptr[vm.m.off++];
                // translate 0 -> 256:
                int l = l_raw;
                if (l == 0) { l = 256; }

                vm.pn += l;

                // perform entire write:
                uint32_t p = vm.m.off;

                vm.e = memory_chip_is_writable(c, a);
                if (vm.e != IOVM1_SUCCESS) {
                    vm.s = IOVM1_STATE_ERRORED;
                    send_end_msg();
                    return vm.e;
                }

                if (c == MEM_SNES_2C00) {
                    vm.e = snescmd_addr_from_chip(c, a, l, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    if (addr == 0x2C00 && l > 1) {
                        // write $2C01.. first:
                        fpga_set_snescmd_addr(addr+1);
                        for (int n = 1; n < l; n++) {
                            fpga_write_snescmd(vm.m.ptr[p + n]);
                        }

                        // write $2C00 byte last to enable nmi exe override:
                        fpga_set_snescmd_addr(addr);
                        fpga_write_snescmd(vm.m.ptr[p]);
                    } else {
                        fpga_set_snescmd_addr(addr);
                        while (l-- > 0) {
                            fpga_write_snescmd(vm.m.ptr[p++]);
                        }
                    }
                } else {
                    vm.e = sram_addr_from_chip(c, a, l, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    set_mcu_addr(addr);
                    FPGA_SELECT();
                    FPGA_TX_BYTE(0x98);   /* WRITE */
                    while (l-- > 0) {
                        FPGA_TX_BYTE(vm.m.ptr[p++]);
                        FPGA_WAIT_RDY();
                    }
                    FPGA_DESELECT();
                }

                // write complete; start next instruction:
                vm.e = IOVM1_SUCCESS;
                return vm.e;
            }
            case IOVM1_OPCODE_WAIT_UNTIL: {
                vm.pn = vm.m.off + 6;

                enum iovm1_cmp_operator q = IOVM1_INST_CMP_OPERATOR(x);

                // memory chip identifier:
                uint8_t c = (enum iovm1_memory_chip)vm.m.ptr[vm.m.off++];
                // 24-bit address:
                uint24_t lo = (uint24_t)(vm.m.ptr[vm.m.off++]);
                uint24_t hi = (uint24_t)(vm.m.ptr[vm.m.off++]) << 8;
                uint24_t bk = (uint24_t)(vm.m.ptr[vm.m.off++]) << 16;
                uint24_t a = bk | hi | lo;

                // comparison byte
                uint8_t v  = vm.m.ptr[vm.m.off++];
                // comparison mask
                uint8_t k  = vm.m.ptr[vm.m.off++];

                // perform loop to wait until (comparison byte & mask) successfully compares to value:

                // initialize 16.666ms deadline timer:
                deadline_us(16666);

                if (c == MEM_SNES_2C00) {
                    vm.e = snescmd_addr_from_chip(c, a, 1, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        // clean up deadline timer:
                        deadline_clean_up();
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    vm.e = IOVM1_ERROR_TIMED_OUT;
                    while (deadline_in_future()) {
                        uint8_t tmp;

                        fpga_set_snescmd_addr(addr);
                        tmp = fpga_read_snescmd();

                        if (iovm1_memory_cmp(q, tmp & k, v)) {
                            vm.e = IOVM1_SUCCESS;
                            break;
                        }
                    }
                } else {
                    vm.e = sram_addr_from_chip(c, a, 1, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        // clean up deadline timer:
                        deadline_clean_up();
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    vm.e = IOVM1_ERROR_TIMED_OUT;
                    while (deadline_in_future()) {
                        uint8_t tmp;

                        tmp = sram_readbyte(addr);

                        if (iovm1_memory_cmp(q, tmp & k, v)) {
                            vm.e = IOVM1_SUCCESS;
                            break;
                        }
                    }
                }

                // clean up deadline timer:
                deadline_clean_up();

                if (vm.e != IOVM1_SUCCESS) {
                    // wait timed out or error occurred:
                    vm.s = IOVM1_STATE_ERRORED;
                }

                // wait complete; start next instruction:
                return vm.e;
            }
            case IOVM1_OPCODE_ABORT_IF: {
                vm.pn = vm.m.off + 6;

                enum iovm1_cmp_operator q = IOVM1_INST_CMP_OPERATOR(x);

                // memory chip identifier:
                enum iovm1_memory_chip c = (enum iovm1_memory_chip)vm.m.ptr[vm.m.off++];
                // 24-bit address:
                uint24_t lo = (uint24_t)(vm.m.ptr[vm.m.off++]);
                uint24_t hi = (uint24_t)(vm.m.ptr[vm.m.off++]) << 8;
                uint24_t bk = (uint24_t)(vm.m.ptr[vm.m.off++]) << 16;
                uint24_t a = bk | hi | lo;

                // comparison byte
                uint8_t v  = vm.m.ptr[vm.m.off++];
                // comparison mask
                uint8_t k  = vm.m.ptr[vm.m.off++];

                uint8_t b;

                // try to read a byte from memory chip:
                if (c == MEM_SNES_2C00) {
                    // special case for 2C00 EXE buffer:
                    uint24_t addr;
                    vm.e = snescmd_addr_from_chip(c, a, 1, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    fpga_set_snescmd_addr(addr);
                    b = fpga_read_snescmd();
                } else {
                    uint24_t addr;
                    vm.e = sram_addr_from_chip(c, a, 1, &addr);
                    if (vm.e != IOVM1_SUCCESS) {
                        vm.s = IOVM1_STATE_ERRORED;
                        send_end_msg();
                        return vm.e;
                    }

                    b = sram_readbyte(addr);
                }

                // test comparison byte against mask and value:
                if (iovm1_memory_cmp(q, b & k, v)) {
                    // abort if true; send an abort message back to the client:
                    vm.s = IOVM1_STATE_ERRORED;
                    vm.e = IOVM1_ERROR_ABORTED;
                    send_end_msg();

                    return vm.e;
                }

                // do not abort if false:
                vm.e = IOVM1_SUCCESS;
                return vm.e;
            }
            default:
                // unknown opcode:
                vm.e = IOVM1_ERROR_UNKNOWN_OPCODE;
                vm.s = IOVM1_STATE_ERRORED;
                send_end_msg();
                return vm.e;
        }
    }

    vm.e = IOVM1_SUCCESS;
    return vm.e;
}

int usbint_handler_dat(void) {
    int ret = 0;
    static int count = 0;
    static int reentrant = 0;
    int bytesSent = 0;
    int streamEnd = 0;

    if (!server_info.data_ready) return ret;

    switch (server_info.opcode) {
    case USBINT_SERVER_OPCODE_IOVM_EXEC: {
        if (reentrant) {
            return ret;
        }
        reentrant = -1;

        // keep the USBA header and error/flags:
        server_info.vm_bytes_sent = 6;
        if (!server_info.error) {
            do {
                // advance the state machine:
                if (iovm1_exec()) {
                    break;
                }
            } while (vm.s < IOVM1_STATE_ENDED);
        }

        // finish command:
        server_info.data_ready = 0;
        server_state = USBINT_SERVER_STATE_IDLE;
        if (server_info.vm_bytes_sent > 0) {
            // clear out any remaining portion of the buffer
            memset((unsigned char *)send_buffer[send_buffer_index] + server_info.vm_bytes_sent, 0x00, server_info.block_size - server_info.vm_bytes_sent);
            // send the final block:
            usbint_send_block(server_info.block_size);
        }

        // don't use the quirky logic beyond the switch block:
        reentrant = 0;
        return ret;
    }
    case USBINT_SERVER_OPCODE_VGET:
    case USBINT_SERVER_OPCODE_GET: {
        if (server_info.space == USBINT_SERVER_SPACE_FILE) {
            server_info.error |= f_lseek(&fh, server_info.offset + count);
            do {
                UINT bytesRead = 0;
                server_info.error |= f_read(&fh, (unsigned char *)send_buffer[send_buffer_index] + bytesSent, server_info.block_size - bytesSent, &bytesRead);
                bytesSent += bytesRead;
                count += bytesRead;
            } while (bytesSent != server_info.block_size && count < server_info.size);

            // close file
            if (count >= server_info.size) {
                f_close(&fh);
            }
        }
        else {
            //PRINT_MSG("[dat]")
            do {
                UINT bytesRead = 0;
                UINT remainingBytes = min(server_info.block_size - bytesSent, server_info.size - count);

                if (server_info.space == USBINT_SERVER_SPACE_SNES) {
                    bytesRead = sram_readblock((uint8_t *)send_buffer[send_buffer_index] + bytesSent, server_info.offset + count, remainingBytes);
                }
                else if (server_info.space == USBINT_SERVER_SPACE_MSU) {
                    bytesRead = msu_readblock((uint8_t *)send_buffer[send_buffer_index] + bytesSent, server_info.offset + count, remainingBytes);
                }
                else if (server_info.space == USBINT_SERVER_SPACE_CMD) {
                    bytesRead = snescmd_readblock((uint8_t *)send_buffer[send_buffer_index] + bytesSent, server_info.offset + count, remainingBytes);
                }
                else {
                    // config
                    uint8_t group = server_info.size & 0xFF;
                    uint8_t index = server_info.offset & 0xFF;
                    uint8_t data  = fpga_read_config(group, index);
                    //printf(" [CONFIG_RD] %2x %2x %2x ", group, index, data);
                    *(uint8_t *)(send_buffer[send_buffer_index] + bytesSent) = data;
                    bytesRead = 1;
                    server_info.size = 1; // reset size/group-valid field
                }
                bytesSent += bytesRead;
                count += bytesRead;

                // generate next offset and size
                if (server_info.opcode == USBINT_SERVER_OPCODE_VGET && count == server_info.size) {
                    while (server_info.vector_count < 8) {
                        server_info.vector_count++;

                        if (cmd_buffer[32 + server_info.vector_count * 4]) {
                            server_info.size = cmd_buffer[32 + server_info.vector_count * 4];

                            server_info.offset  = 0;
                            server_info.offset |= cmd_buffer[33 + server_info.vector_count * 4]; server_info.offset <<= 8;
                            server_info.offset |= cmd_buffer[34 + server_info.vector_count * 4]; server_info.offset <<= 8;
                            server_info.offset |= cmd_buffer[35 + server_info.vector_count * 4]; server_info.offset <<= 0;

                            count = 0;
                            break;
                        }
                    }
                }
            } while (bytesSent != server_info.block_size && count < server_info.size);
        }

        break;
    }
    case USBINT_SERVER_OPCODE_LS: {
        uint8_t *name = NULL;
        do {
            int fiContPrev = fiCont;
            fiCont = 0;

            /* Read the next entry */
            if (server_info.error || (!fiContPrev && f_readdir(&dh, &fi) != FR_OK)) {
                send_buffer[send_buffer_index][bytesSent++] = 0xFF;
                count = 1; // signal done
                f_closedir(&dh);
                break;
            }

            /* Abort if none was found */
            if (!fi.fname[0]) {
                send_buffer[send_buffer_index][bytesSent++] = 0xFF;
                count = 1; // signal done
                f_closedir(&dh);
                break;
            }

            /* Skip volume labels */
            if (fi.fattrib & AM_VOL)
                continue;

            /* Select between LFN and 8.3 name */
            if (fi.lfname[0]) {
                name = (uint8_t*)fi.lfname;
            }
            else {
                name = (uint8_t*)fi.fname;
                strlwr((char *)name);
            }

            // check for id(1) string(strlen + 1) is does not go past index
            if (bytesSent + 1 + strlen((TCHAR*)name) + 1 <= server_info.block_size) {
                send_buffer[send_buffer_index][bytesSent++] = (fi.fattrib & AM_DIR) ? 0 : 1;
                strcpy((TCHAR*)send_buffer[send_buffer_index] + bytesSent, (TCHAR*)name);
                bytesSent += strlen((TCHAR*)name) + 1;
                // send string
            }
            else {
                // send continuation.  overwrite string flag to simplify parsing
                send_buffer[send_buffer_index][bytesSent++] = 2;
                fiCont = 1;
                break;
            }
        } while (bytesSent < server_info.block_size);
        break;
    }
    case USBINT_SERVER_OPCODE_STREAM: {
        static uint32_t preload_count = 0;
        static uint16_t head_pointer = 0;
        // perform stream operation

        if (stream_state == USBINT_SERVER_STREAM_STATE_INIT) {
            count = 0;

            // don't reset the head pointer on burst reads.  it may try and read out the entire buffer which is ok.  that data should be discarded.
            if (!(server_info.flags & USBINT_SERVER_FLAGS_STREAMBURST) || preload_count == 0) head_pointer = get_msu_pointer() & 0xFFFF;

            // burst reads don't preload state
            preload_count = (server_info.flags & USBINT_SERVER_FLAGS_STREAMBURST) ? 0x50000 : 0; // VRAM + PPUREG + CPUREG + DMAREG

            // don't reset the head pointer on burst reads.  it may try and read out the entire buffer which is ok.  that data should be discarded.
            //if (!(server_info.flags & USBINT_SERVER_FLAGS_STREAMBURST)) head_pointer = get_msu_pointer() & 0xFFFF;

            stream_state = USBINT_SERVER_STREAM_STATE_ACTIVE;
        }

        // check preload
        if ((count % 8 == 0) && (preload_count < 0x50000)) {
            UINT bytesRead = 0;

            // send state
            bytesRead = sram_readblock((uint8_t *)send_buffer[send_buffer_index] + bytesSent, 0xF50000 + preload_count, 64 - bytesSent);
            bytesSent += bytesRead;

            preload_count += bytesRead;
        }
        else {
            UINT bytesRead = 0;
             // read queue state
            uint32_t pointers = get_msu_pointer();
            //uint16_t frame_pointer = (pointers >> 16) & 0xFFFF;
            uint16_t tail_pointer = (pointers >> 0) & 0xFFFF;

            //printf("head: %hu, tail: %hu\n", head_pointer, tail_pointer);

            // fill buffer up to pointer
            uint16_t offset = (head_pointer > tail_pointer) ? 0x800 : 0x0;
            uint16_t bytesToRead = (tail_pointer - (head_pointer + offset)) & 0x7FFF;
            bytesRead = msu_readblock((uint8_t *)send_buffer[send_buffer_index] + bytesSent, head_pointer, min(64, bytesToRead));

            bytesSent += bytesRead;
            head_pointer = head_pointer + bytesRead;
            if (head_pointer >= 0x7800) head_pointer = (head_pointer + 0x800) & 0x7FFF;
        }

        count++;

        // Fill remaining part of the buffer with NOPs.
        // FIXME: if we do DMA compression we need to handled odd counts (probably add byte padding)
        memset((unsigned char *)send_buffer[send_buffer_index] + bytesSent, 0xFF, server_info.block_size - bytesSent);
        streamEnd = bytesSent < server_info.block_size ? 1 : 0;
        bytesSent = server_info.block_size;

        break;
    }
    default: {
        // send back a single data beat with all 0xFF's
        memset((unsigned char *)send_buffer[send_buffer_index], 0xFF, server_info.block_size);
        //bytesSent = server_info.block_size;
        break;
    }
    }

    if (server_state != USBINT_SERVER_STATE_HANDLE_STREAM) {
        if (count >= server_info.size) {
            // clear out any remaining portion of the buffer
            memset((unsigned char *)send_buffer[send_buffer_index] + bytesSent, 0x00, server_info.block_size - bytesSent);
        }
    }

    if (bytesSent) {
        // printing state seems to cause some locks
        //PRINT_STATE(server_state);
        enum usbint_server_state_e old_server_state = server_state;

        if (server_state != USBINT_SERVER_STATE_HANDLE_STREAM || ((server_info.flags & USBINT_SERVER_FLAGS_STREAMBURST) && streamEnd)) {
            if (count >= server_info.size || server_state == USBINT_SERVER_STATE_HANDLE_STREAM) {
                //PRINT_FUNCTION();
                //PRINT_MSG("[ldat]")

                //PRINT_STATE(server_state);
                server_info.data_ready = 0;
                server_state = USBINT_SERVER_STATE_IDLE;
                //PRINT_STATE(server_state);

                //PRINT_DAT((int)count, (int)server_info.size);

                count = 0;

                //PRINT_END();
            }
        }

        if (old_server_state == USBINT_SERVER_STATE_HANDLE_DATPUSH) {
            // polling push
            //PRINT_MSG("[push]")
            usbint_send_block(server_info.block_size);
            //PRINT_MSG("[push_done]")
        }
        else {
            // TODO: move buffer fill after this to speed up perf
            // interrupt push
            CDC_block_init((unsigned char*)send_buffer[send_buffer_index], server_info.block_size);
            send_buffer_index = (send_buffer_index + 1) & 0x1;
        }
    }

    return ret;
}

int usbint_handler_exe(void) {
    int ret = 0;

    PRINT_FUNCTION();
    PRINT_MSG("[hexe]")

    if (!server_info.error) {
        // clear out existing patch by overwriting with a 00
        fpga_set_snescmd_addr(SNESCMD_EXE);
        fpga_write_snescmd(0x00);

        // wait to make sure we are out of the code.  one frame should do
        // TODO: could check with the fpga for this
        sleep_ms(16);

        for (int i = 1; i < server_info.size; i++) {
            uint8_t val = sram_readbyte(server_info.offset + i);
            fpga_write_snescmd(val);
        }
        // write exit
        fpga_write_snescmd(0x6C);
        fpga_write_snescmd(0xEA);
        fpga_write_snescmd(0xFF);

        fpga_set_snescmd_addr(SNESCMD_EXE);
        fpga_write_snescmd(sram_readbyte(server_info.offset));
    }

    // TODO: do we need this if we get a EXE opcode?
    //PRINT_STATE(server_state);
    //server_state = USBINT_SERVER_STATE_IDLE;
    //PRINT_STATE(server_state);

    PRINT_END();

    return ret;
}
