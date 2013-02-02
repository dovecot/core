/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-command.h"
#include "mail-session.h"
#include "mail-user.h"
#include "mail-domain.h"
#include "mail-ip.h"
#include "stats-settings.h"
#include "global-memory.h"

size_t global_used_memory = 0;

static bool global_memory_free_something(void)
{
	size_t orig_used_memory = global_used_memory;

	mail_commands_free_memory();
	if (global_used_memory > stats_settings->memory_limit)
		mail_sessions_free_memory();
	if (global_used_memory > stats_settings->memory_limit)
		mail_users_free_memory();
	if (global_used_memory > stats_settings->memory_limit)
		mail_ips_free_memory();
	if (global_used_memory > stats_settings->memory_limit)
		mail_domains_free_memory();

	return global_used_memory < orig_used_memory;
}

void global_memory_alloc(size_t size)
{
	i_assert(size < (size_t)-1 - global_used_memory);
	global_used_memory += size;

	while (global_used_memory > stats_settings->memory_limit) {
		if (!global_memory_free_something())
			break;
	}
}

void global_memory_free(size_t size)
{
	i_assert(size <= global_used_memory);
	global_used_memory -= size;
}
