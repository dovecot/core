#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "client.h"

/* max. number of IMAP argument elements to accept. The maximum memory usage
   for command from user is around MAX_INBUF_SIZE * MAX_IMAP_ARG_ELEMENTS */
#define MAX_IMAP_ARG_ELEMENTS 128

#define DEFAULT_MAX_CUSTOM_FLAG_LENGTH 50

extern struct ioloop *ioloop;
extern unsigned int max_custom_flag_length, mailbox_check_interval;

#endif
