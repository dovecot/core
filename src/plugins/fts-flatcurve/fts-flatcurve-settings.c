/* Copyright (c) 2023 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "fts-flatcurve-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("fts_flatcurve_"#name, name, struct fts_flatcurve_settings)

/* <settings checks> */
#define FTS_FLATCURVE_MAX_TERM_SIZE_MAX 200
/* </settings checks> */

static const struct setting_define fts_flatcurve_setting_defines[] = {
	/* For now this filter just allows grouping the settings
	   like it is possible in the other fts_backends. */
	{ .type = SET_FILTER_NAME, .key = FTS_FLATCURVE_FILTER },
	DEF(UINT, commit_limit),
	DEF(UINT, max_term_size),
	DEF(UINT, min_term_size),
	DEF(UINT, optimize_limit),
	DEF(UINT, rotate_count),
	DEF(TIME_MSECS, rotate_time),
	DEF(BOOL, substring_search),
	SETTING_DEFINE_LIST_END
};

static const struct fts_flatcurve_settings fts_flatcurve_default_settings = {
	.commit_limit     =   500,
	.max_term_size    =    30,
	.min_term_size    =     2,
	.optimize_limit   =    10,
	.rotate_count     =  5000,
	.rotate_time      =  5000,
	.substring_search = FALSE,
};

/* <settings checks> */
static bool fts_flatcurve_settings_check(void *_set, pool_t pool,
					 const char **error_r);
/* </settings checks> */

const struct setting_parser_info fts_flatcurve_setting_parser_info = {
	.name = "fts_flatcurve",

	.defines = fts_flatcurve_setting_defines,
	.defaults = &fts_flatcurve_default_settings,
	.check_func = fts_flatcurve_settings_check,

	.struct_size = sizeof(struct fts_flatcurve_settings),
	.pool_offset1 = 1 + offsetof(struct fts_flatcurve_settings, pool),
};

/* <settings checks> */
static bool fts_flatcurve_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					 const char **error_r)
{
	struct fts_flatcurve_settings *set = _set;

	if (set->max_term_size > FTS_FLATCURVE_MAX_TERM_SIZE_MAX) {
		*error_r = t_strdup_printf(
			"Invalid fts_flatcurve_max_term_size '%u', "
			"allowed values: 0..%d",
			set->max_term_size, FTS_FLATCURVE_MAX_TERM_SIZE_MAX);
		return FALSE;
	}

	return TRUE;
}
/* </settings checks> */
