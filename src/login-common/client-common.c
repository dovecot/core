/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "client-common.h"

void client_syslog(struct client *client, const char *format, ...)
{
	const char *addr;
	va_list args;

	addr = net_ip2addr(&client->ip);
	if (addr == NULL)
		addr = "??";

	t_push();
	va_start(args, format);
	i_info("%s [%s]", t_strdup_vprintf(format, args), addr);
	va_end(args);
	t_pop();
}
