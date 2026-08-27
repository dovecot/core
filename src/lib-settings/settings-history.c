/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "version.h"
#include "settings-history.h"

#include "settings-history-core.h"

static struct settings_history history;

/* Sort the newest versions first. The users of the history stop looking as
   soon as they see a version that is not newer than the config version. */
static int
settings_history_default_cmp(const struct setting_history_default *d1,
			     const struct setting_history_default *d2)
{
	return version_cmp(d2->version, d1->version);
}

static int
settings_history_rename_cmp(const struct setting_history_rename *r1,
			    const struct setting_history_rename *r2)
{
	return version_cmp(r2->version, r1->version);
}

static int
settings_history_value_cmp(const struct setting_history_value *v1,
			   const struct setting_history_value *v2)
{
	return version_cmp(v2->version, v1->version);
}

static int
settings_history_deprecate_cmp(const struct setting_history_deprecate *d1,
			       const struct setting_history_deprecate *d2)
{
	return version_cmp(d2->version, d1->version);
}

static void settings_history_free(void)
{
	array_free(&history.defaults);
	array_free(&history.renames);
	array_free(&history.values);
	array_free(&history.deprecates);
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
	i_array_init(&history.values,
		     N_ELEMENTS(settings_history_core_values) + 16);
	array_append(&history.values,
		     settings_history_core_values,
		     N_ELEMENTS(settings_history_core_values));
	i_array_init(&history.deprecates,
		     N_ELEMENTS(settings_history_core_deprecates) + 16);
	array_append(&history.deprecates,
		     settings_history_core_deprecates,
		     N_ELEMENTS(settings_history_core_deprecates));

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
		array_sort(&history->values,
			   settings_history_value_cmp);
		array_sort(&history->deprecates,
			   settings_history_deprecate_cmp);
		history->sort_pending = FALSE;
	}
	return history;
}

const char *settings_history_translate_key(const char *key)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_rename *rename;
	unsigned int max_iterations = array_count(&history->renames);
	bool changed;

	do {
		const char *p = strrchr(key, '/');
		const char *prefix = p == NULL ? "" :
			t_strdup_until(key, p + 1);
		const char *last_key = p == NULL ? key : p + 1;

		changed = FALSE;
		array_foreach(&history->renames, rename) {
			if (strcmp(rename->old_key, last_key) != 0)
				continue;

			const char *new_key = rename->new_key;
			/* The new key may have a filter prefix, e.g.
			   imapc/client_auth_authzid. If the key already is
			   inside that filter, drop the prefix - otherwise a
			   nested filter with the same name would be used. */
			if (strchr(new_key, '/') != NULL) {
				const char *filter_prefix = t_strconcat(
					t_strcut(new_key, '/'), "/", NULL);
				if (str_ends_with(prefix, filter_prefix))
					new_key = strchr(new_key, '/') + 1;
			}
			key = t_strconcat(prefix, new_key, NULL);
			changed = TRUE;
			break;
		}
	} while (changed && max_iterations-- > 0);
	return key;
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

void settings_history_register_values(
	const struct setting_history_value *values, unsigned int count)
{
	struct settings_history *history = settings_history_get_unsorted();

	array_append(&history->values, values, count);
	history->sort_pending = TRUE;
}

void settings_history_register_deprecates(
	const struct setting_history_deprecate *deprecates, unsigned int count)
{
	struct settings_history *history = settings_history_get_unsorted();

	array_append(&history->deprecates, deprecates, count);
	history->sort_pending = TRUE;
}
