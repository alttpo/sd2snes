/* ___INGO___ */

#include <arm/NXP/LPC17xx/LPC17xx.h>
#include "power.h"
#include "bits.h"
#include "config.h"
#include "timer.h"
#include "clock.h"
#include "uart.h"
#include "sdnative.h"
#include "snes.h"
#include "led.h"
#include "cfg.h"
#include "cic.h"

extern volatile int sd_changed;
extern volatile int reset_changed;
extern volatile int reset_pressed;

volatile tick_t msTicks;  /*  1ms ticks */
volatile tick_t ticks;    /* 10ms ticks */
volatile int wokefromrit;

void __attribute__((weak,noinline)) SysTick_Hook(void) {
  /* Empty function for hooking the systick handler */
}

/* Systick handler: called every 10ms from interrupt handler */
void SysTick_10msHandler(void) {
  ticks++;
  static int warmup = 0;
  static uint16_t sdch_state = 0;
  static uint16_t reset_state = 0;
  sdch_state = (sdch_state << 1) | SDCARD_DETECT | 0xe000;
  if(warmup > WARMUP_TICKS && ((sdch_state == 0xf000) || (sdch_state == 0xefff))) {
    sd_changed = 1;
  }
  reset_state = (reset_state << 1) | get_snes_reset() | 0xff00;
  if((reset_state == 0xff80) || (reset_state == 0xff7f)) {
    reset_pressed = (reset_state == 0xff7f);
    reset_changed = 1;
    if(reset_pressed) {
      cic_init(0);
    } else {
      cic_init(cfg_is_pair_mode_allowed());
    }
  }
  led_error();
  sdn_changed();
  SysTick_Hook();
  if(warmup <= WARMUP_TICKS) warmup++;
}

/* Systick interrupt handler: called every 1ms */
void SysTick_Handler(void) {
  static int msec = 0;

  msTicks++;
  if (msec++ >= 10) {
    msec = 0;
    SysTick_10msHandler();
  }
}

void __attribute__((weak,noinline)) RIT_Hook(void) {
}

void RIT_IRQHandler(void) {
  LPC_RIT->RICTRL = BV(RITINT);
  NVIC_ClearPendingIRQ(RIT_IRQn);
  wokefromrit = 1;
  RIT_Hook();
}

void timer_init(void) {
  /* turn on power to RIT */
  BITBAND(LPC_SC->PCONP, PCRIT) = 1;

  /* clear RIT mask */
  LPC_RIT->RIMASK = 0; /*xffffffff;*/

  /* PCLK_RIT = CCLK */
  BITBAND(LPC_SC->PCLKSEL1, 27) = 0;
  BITBAND(LPC_SC->PCLKSEL1, 26) = 1;

  /* PCLK_TIMER3 = CCLK/4 */
  BITBAND(LPC_SC->PCLKSEL1, 15) = 0;
  BITBAND(LPC_SC->PCLKSEL1, 14) = 0;

  /* enable timer 3 */
  BITBAND(LPC_SC->PCLKSEL1, PCLK_TIMER3) = 1;

  /* enable SysTick */
  SysTick_Config((SysTick->CALIB & SysTick_CALIB_TENMS_Msk) / 10);
}

void delay_us(unsigned int time) {
  /* Prepare RIT */
  LPC_RIT->RICOUNTER = 0;
  LPC_RIT->RICOMPVAL = (CONFIG_CPU_FREQUENCY / 1000000) * time;
  LPC_RIT->RICTRL    = BV(RITEN) | BV(RITINT);

  /* Wait until RIT signals an interrupt */
  while (!(BITBAND(LPC_RIT->RICTRL, RITINT))) ;

  /* Disable RIT */
  LPC_RIT->RICTRL = 0;
}

void delay_ms(unsigned int time) {
  /* Prepare RIT */
  LPC_RIT->RICOUNTER = 0;
  LPC_RIT->RICOMPVAL = (CONFIG_CPU_FREQUENCY / 1000) * time;
  LPC_RIT->RICTRL    = BV(RITEN) | BV(RITINT);

  /* Wait until RIT signals an interrupt */
  while (!(BITBAND(LPC_RIT->RICTRL, RITINT))) ;

  /* Disable RIT */
  LPC_RIT->RICTRL = 0;
}

void sleep_ms(unsigned int time) {

  NVIC_EnableIRQ(RIT_IRQn);
  wokefromrit = 0;
  /* Prepare RIT */
  LPC_RIT->RICOUNTER = 0;
  LPC_RIT->RICOMPVAL = (CONFIG_CPU_FREQUENCY / 1000) * time;
  LPC_RIT->RICTRL    = BV(RITEN) | BV(RITINT);

  /* Wait until RIT signals an interrupt */
//uart_putc(';');
  while(!wokefromrit) {
    __WFI();
  }
  NVIC_DisableIRQ(RIT_IRQn);
  /* Disable RIT */
  LPC_RIT->RICTRL = BV(RITINT);
}
