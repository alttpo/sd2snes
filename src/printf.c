/* Small, noncompliant, not-full-featured printf implementation
 *
 *
 * Copyright (c) 2010, Ingo Korb
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Ingo Korb nor the
 *       names of the contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * FIXME: Selection of output function should be more flexible
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "config.h"
#include "uart.h"
#include "ff.h"
#include "timer.h"
#include "led.h"

#define outfunc(x) uart_putc(x)

#define FLAG_ZEROPAD   1
#define FLAG_LEFTADJ   2
#define FLAG_BLANK     4
#define FLAG_FORCESIGN 8
#define FLAG_WIDTH     16
#define FLAG_LONG      32
#define FLAG_UNSIGNED  64
#define FLAG_NEGATIVE  128

/* Digits used for conversion */
static const char hexdigits[] = "0123456789abcdef";

/* Temporary buffer used for numbers - just large enough for 32 bit in octal */
static char buffer[12];

/* Output string length */
static unsigned int outlength;

/* Output pointer */
static char *outptr;
static int maxlen;

/* printf */
static void outchar(char x) {
  if (maxlen) {
    maxlen--;
    outfunc(x);
    outlength++;
  }
}

/* sprintf */
static void outstr(char x) {
  if (maxlen) {
    maxlen--;
    *outptr++ = x;
    outlength++;
  }
}

static int internal_nprintf(void (*output_function)(char c), const char *fmt, va_list ap) {
  unsigned int width;
  unsigned int flags;
  unsigned int base = 0;
  char *ptr = NULL;

  outlength = 0;

  while (*fmt) {
    while (1) {
      if (*fmt == 0)
        goto end;

      if (*fmt == '%') {
        fmt++;
        if (*fmt != '%')
          break;
      }

      output_function(*fmt++);
    }

    flags = 0;
    width = 0;

    /* read all flags */
    do {
      if (flags < FLAG_WIDTH) {
        switch (*fmt) {
        case '0':
          flags |= FLAG_ZEROPAD;
          continue;

        case '-':
          flags |= FLAG_LEFTADJ;
          continue;

        case ' ':
          flags |= FLAG_BLANK;
          continue;

        case '+':
          flags |= FLAG_FORCESIGN;
          continue;
        }
      }

      if (flags < FLAG_LONG) {
        if (*fmt >= '0' && *fmt <= '9') {
          unsigned char tmp = *fmt - '0';
          width = 10*width + tmp;
          flags |= FLAG_WIDTH;
          continue;
        }

        if (*fmt == 'h')
          continue;

        if (*fmt == 'l') {
          flags |= FLAG_LONG;
          continue;
        }
      }

      break;
    } while (*fmt++);

    /* Strings */
    if (*fmt == 'c' || *fmt == 's') {
      switch (*fmt) {
      case 'c':
        buffer[0] = va_arg(ap, int);
        ptr = buffer;
        break;

      case 's':
        ptr = va_arg(ap, char *);
        break;
      }

      goto output;
    }

    /* Numbers */
    switch (*fmt) {
    case 'u':
      flags |= FLAG_UNSIGNED;
    case 'd':
      base = 10;
      break;

    case 'o':
      base = 8;
      flags |= FLAG_UNSIGNED;
      break;

    case 'p': // pointer
      output_function('0');
      output_function('x');
      width -= 2;
    case 'x':
    case 'X':
      base = 16;
      flags |= FLAG_UNSIGNED;
      break;
    }

    unsigned int num;

    if (!(flags & FLAG_UNSIGNED)) {
      int tmp = va_arg(ap, int);
      if (tmp < 0) {
        num = -tmp;
        flags |= FLAG_NEGATIVE;
      } else
        num = tmp;
    } else {
      num = va_arg(ap, unsigned int);
    }

    /* Convert number into buffer */
    ptr = buffer + sizeof(buffer);
    *--ptr = 0;
    do {
      *--ptr = hexdigits[num % base];
      num /= base;
    } while (num != 0);

    /* Sign */
    if (flags & FLAG_NEGATIVE) {
      output_function('-');
      width--;
    } else if (flags & FLAG_FORCESIGN) {
      output_function('+');
      width--;
    } else if (flags & FLAG_BLANK) {
      output_function(' ');
      width--;
    }

  output:
    /* left padding */
    if ((flags & FLAG_WIDTH) && !(flags & FLAG_LEFTADJ)) {
      while (strlen(ptr) < width) {
        if (flags & FLAG_ZEROPAD)
          output_function('0');
        else
          output_function(' ');
        width--;
      }
    }

    /* data */
    while (*ptr) {
      output_function(*ptr++);
      if (width)
        width--;
    }

    /* right padding */
    if (flags & FLAG_WIDTH) {
      while (width) {
        output_function(' ');
        width--;
      }
    }

    fmt++;
  }

 end:
  return outlength;
}

int printf(const char *format, ...) {
  va_list ap;
  int res;

  maxlen = -1;
  va_start(ap, format);
  res = internal_nprintf(outchar, format, ap);
  va_end(ap);
  return res;
}

int snprintf(char *str, size_t size, const char *format, ...) {
  va_list ap;
  int res;

  maxlen = size;
  outptr = str;
  va_start(ap, format);
  res = internal_nprintf(outstr, format, ap);
  va_end(ap);
  if (res < size)
    str[res] = 0;
  return res;
}

/* Required for gcc compatibility */
int puts(const char *str) {
  uart_puts(str);
  uart_putc('\n');
  return 0;
}

#undef putchar
int putchar(int c) {
  uart_putc(c);
  return 0;
}

static FIL log_file_handle;
static volatile int log_opened = 0;
static volatile char log_last_c = '\n';
static volatile FRESULT log_fr = FR_OK;
static volatile UINT log_buf_pos = 0;
static char log_buf[512] __attribute__((aligned(4)));

void lpanic(uint8_t led_states) {
  led_std();
  while(1) {
    rdyled((led_states >> 2) & 1);
    readled((led_states >> 1) & 1);
    writeled(led_states & 1);
    delay_ms(100);
    rdyled(0);
    readled(0);
    writeled(0);
    delay_ms(100);
  }
}

/* writes a character to /sd2snes/log.txt file; buffered up to '\n' or every 512 bytes, whichever comes first */
static void outlog(char c) {
  if (maxlen) {
    maxlen--;
    outlength++;
  }

  /* don't keep repeating the same mistakes: */
  if (log_fr != FR_OK) {
    lpanic(1|2|4);
    return;
  }

  /* open the log.txt file for writing first time */
  if (!log_opened) {
    log_fr = f_open(&log_file_handle, (TCHAR*)"/sd2snes/log.txt", FA_CREATE_ALWAYS | FA_WRITE);
    if (log_fr != FR_OK) {
      //printf("outlog: f_open /sd2snes/log.txt failed; fr = %d\n", log_fr);
      lpanic(1|2|4);
      return;
    }
    /* don't f_lseek to end of file to append; we want fresh log.txt every boot */

    log_opened = -1;
    log_buf_pos = 0;
  }

  /* start the new line with the current tick count for timing info: */
  if (log_last_c == '\n') {
    tick_t t = getMsTicks();

    /* cannot recurse with internal_nprintf() due to global usage: */
    /*buf_pos += snprintf(buf, 512, "%7u.%02u: ", secs, msec);*/

    log_buf[log_buf_pos+11] = ' ';
    log_buf[log_buf_pos+10] = ':';
    log_buf[log_buf_pos+9] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+8] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+7] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+6] = '.';
    log_buf[log_buf_pos+5] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+4] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+3] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+2] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+1] = (t % 10) + '0'; t /= 10;
    log_buf[log_buf_pos+0] = (t % 10) + '0';

    log_buf_pos += 12;
  }

  /* buffer the character */
  log_buf[log_buf_pos++] = c;
  log_last_c = c;

  /* write to disk on newlines or if buffer size reached: */
  if ((log_buf_pos >= 512) || (c == '\n')) {
    UINT bytes_written = 0;

    log_fr = f_write(&log_file_handle, log_buf, log_buf_pos, &bytes_written);
    if (log_fr != FR_OK) {
      //printf("outlog: f_write to /sd2snes/log.txt failed; fr = %d\n", log_fr);
      lpanic(1|2|4);
      return;
    }
    if (bytes_written < log_buf_pos) {
      //printf("outlog: f_write to /sd2snes/log.txt did not write enough bytes; %d < %d\n", bytes_written, log_buf_pos);
      lpanic(1|2|4);
      return;
    }

    log_buf_pos = 0;

    /* sync to fs */
    log_fr = f_sync(&log_file_handle);
    if (log_fr != FR_OK) {
      //printf("outlog: f_sync to /sd2snes/log.txt failed; fr = %d\n", fr);
      lpanic(1|2|4);
      return;
    }
  }
}

/* logs a formatted message to /sd2snes/log.txt using outlog() above */
int lprintf(const char *format, ...) {
  va_list ap;
  int res;

  va_start(ap, format);
  res = internal_nprintf(outlog, format, ap);
  va_end(ap);

  return res;
}
