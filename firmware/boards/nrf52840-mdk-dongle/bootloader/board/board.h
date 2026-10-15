/*
 * The Makerdiary nRF52840 MDK USB Dongle as its factory UF2 bootloader (0.7.1) sees it,
 * read back from that binary: the same pins, USB identity and drive. Derived from
 * Adafruit_nRF52_Bootloader's src/boards/mdk_nrf52840_dongle/board.h, whose own values
 * (VID 239A, P0.18 "unusable: RESET") do not describe this unit.
 *
 * The MIT License (MIT)
 * Copyright (c) 2018 gpshead (krypto.org) for Adafruit Industries
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions: The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _NRF52840_MDK_USB_DONGLE_H_
#define _NRF52840_MDK_USB_DONGLE_H_

#define _PINNUM(port, pin)    ((port)*32 + (pin))

/*------------------------------------------------------------------*/
/* LED: one RGB LED, active low. The factory build drives it as an RGB status LED (green
 * while the drive is mounted) and also inits red as the primary LED.
 *------------------------------------------------------------------*/
#define LEDS_NUMBER           1
#define LED_PRIMARY_PIN       _PINNUM(0, 23)
#define LED_STATE_ON          0

#define LED_RGB_RED_PIN       _PINNUM(0, 23)
#define LED_RGB_GREEN_PIN     _PINNUM(0, 22)
#define LED_RGB_BLUE_PIN      _PINNUM(0, 24)
#define BOARD_RGB_BRIGHTNESS  0x404040

/*------------------------------------------------------------------*/
/* BUTTON: the USER button on P0.18, a plain input (UICR PSELRESET is not set on this
 * unit, and nothing here may set it). P0.19 is not connected; upstream needs a second
 * button, and with the pull-up it never reads as pressed.
 *------------------------------------------------------------------*/
#define BUTTONS_NUMBER        2
#define BUTTON_1              _PINNUM(0, 18)
#define BUTTON_2              _PINNUM(0, 19)
#define BUTTON_PULL           NRF_GPIO_PIN_PULLUP

/*------------------------------------------------------------------*/
/* USB: the strings double as the BLE ones upstream.
 *------------------------------------------------------------------*/
#define BLEDIS_MANUFACTURER   "Makerdiary"
#define BLEDIS_MODEL          "nRF52840-MDK-USB-DONGLE"

/* Also the CF2 board ID (VID << 16 | PID) the factory bootloader checks before it
 * accepts a self-update: 0x2886F00F. */
#define USB_DESC_VID           0x2886
#define USB_DESC_UF2_PID       0xF00F
#define USB_DESC_CDC_ONLY_PID  0xF00F

/*------------------------------------------------------------------*/
/* Flash: the drive writes 0x1000..BOARD_APP_FLASH_END and nothing else. Above it lie
 * the vault (0x97000..0xC8000) and the filesystem a firmware keeps (0xC8000..0xF4000).
 * The same boundary as FLASH in the firmware's memory.x and VAULT_BASE in its main.rs.
 *
 * The on-board test build (VKEY_AS_APP, bootloader/test/) runs from 0x1000 under the
 * factory bootloader, so its drive writes only a scratch window above itself and stages
 * a self-update at the top of it. Its own label tells its drive from a bootloader's.
 *------------------------------------------------------------------*/
#ifdef VKEY_AS_APP
#define BOARD_TEST_SCRATCH    0x40000
#define BOARD_APP_FLASH_END   0x80000
#define UF2_VOLUME_LABEL      "VKEYTEST   "
#else
#define BOARD_APP_FLASH_END   0x97000
#define UF2_VOLUME_LABEL      "UF2BOOT    "
#endif

/* The app's signature slot (src/signature.h): the last page of the window, which the
 * app itself never reaches - memory.x ends its FLASH here. */
#define BOARD_APP_SLOT        (BOARD_APP_FLASH_END - 0x1000)

#define UF2_PRODUCT_NAME   "Makerdiary nRF52840 MDK USB Dongle"
#define UF2_BOARD_ID       "nRF52840-MDK-USB-DONGLE"
#define UF2_INDEX_URL      "https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle"

#endif /* _NRF52840_MDK_USB_DONGLE_H_ */
