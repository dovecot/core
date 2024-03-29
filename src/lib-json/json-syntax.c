/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "json-syntax.h"

/* Character bit mappings:

   (1<<0) =>  %x20-21 / %x23-5B / %x5D-10FFFF ; 'uchar'
   (1<<1) =>  %x00-08 / %x0b-0c / %x0e-1F     ; 'control'
   (1<<2) =>  %x09 / %x0A / %x0D / %x20       ; 'ws'
   (1<<3) =>  "0"-"9"                         ; 'digit'
 */

const unsigned char json_uchar_char_mask   = (1<<0);
const unsigned char json_control_char_mask = (1<<1);
const unsigned char json_ws_char_mask      = (1<<2);
const unsigned char json_digit_char_mask   = (1<<3);

const unsigned char json_char_lookup[128] = {
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // 0x00
	0x02, 0x04, 0x04, 0x02, 0x02, 0x04, 0x02, 0x02, // 0x08
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // 0x10
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, // 0x18
	0x05, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x20
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x28
	0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // 0x30
	0x09, 0x09, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x38
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x40
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x48
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x50
	0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, // 0x58
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x60
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x68
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x70
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // 0x78
};

