/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "version.h"
#include "settings-history.h"

#include "settings-history-core.h"

static struct settings_history history;

static int
settings_history_default_cmp(const struct setting_history_default *d1,
			     const struct setting_history_default *d2)
{
	return version_cmp(d1->version, d2->version);
}

static int
settings_history_rename_cmp(const struct setting_history_rename *r1,
			    const struct setting_history_rename *r2)
{
	return version_cmp(r1->version, r2->version);
}

static void settings_history_free(void)
{
	array_free(&history.defaults);
	array_free(&history.renames);
}

static struct settings_history *settings_history_get_unsorted(void)
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

struct settings_history *settings_history_get(void)
{
	struct settings_history *history = settings_history_get_unsorted();
	if (history->sort_pending) {
		array_sort(&history->defaults,
			   settings_history_default_cmp);
		array_sort(&history->renames,
			   settings_history_rename_cmp);
		history->sort_pending = FALSE;
	}
	return history;
}

void settings_history_register_defaults(
	const struct setting_history_default *defaults, unsigned int count)
{
	struct settings_history *history = settings_history_get_unsorted();

	array_append(&history->defaults, defaults, count);
	history->sort_pending = TRUE;
}

void settings_history_register_renames(
	const struct setting_history_rename *renames, unsigned int count)
{
	struct settings_history *history = settings_history_get_unsorted();

	array_append(&history->renames, renames, count);
	history->sort_pending = TRUE;
}
