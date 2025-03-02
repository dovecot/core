/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-history.h"

#include "settings-history-core.c"

static struct settings_history history;

static void settings_history_free(void)
{
	array_free(&history.defaults);
	array_free(&history.renames);
}

struct settings_history *settings_history_get(void)
{
	if (array_is_created(&history.defaults))
		return &history;

	i_array_init(&history.defaults,
		     N_ELEMENTS(settings_history_core_defaults) + 16);
	array_append(&history.defaults,
		     settings_history_core_defaults,
		     N_ELEMENTS(settings_history_core_defaults));
	i_array_init(&history.renames,
		     N_ELEMENTS(settings_history_core_renames) + 16);
	array_append(&history.renames,
		     settings_history_core_renames,
		     N_ELEMENTS(settings_history_core_renames));

	lib_atexit(settings_history_free);
	return &history;
}

void settings_history_register_defaults(
	const struct setting_history_default *defaults, unsigned int count)
{
	struct settings_history *history = settings_history_get();

	array_append(&history->defaults, defaults, count);
}

void settings_history_register_renames(
	const struct setting_history_rename *renames, unsigned int count)
{
	struct settings_history *history = settings_history_get();

	array_append(&history->renames, renames, count);
}
