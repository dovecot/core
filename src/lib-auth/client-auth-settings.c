/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str-sanitize.h"
#include "settings.h"
#include "settings-parser.h"

#include "client-auth-settings.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("client_auth_"#name, name, \
				     struct client_auth_settings)

static const struct setting_define client_auth_setting_defines[] = {
	DEF(STR, mechanism),
	DEF(STR, authid),
	DEF(STR, authzid),
	DEF(STR, password),

	{ .type = SET_FILTER_ARRAY, .key = CLIENT_AUTH_SETTINGS_FILTER,
	  .offset = offsetof(struct client_auth_settings, mechanisms),
	  .filter_array_field_name = "client_auth_mechanism" },

	SETTING_DEFINE_LIST_END
};

static const struct client_auth_settings client_auth_default_settings = {
	.mechanism = "",
	.authid = "",
	.authzid = "",
	.password = "",

	.mechanisms = ARRAY_INIT,
};

const struct setting_parser_info client_auth_setting_parser_info = {
	.name = "client_auth",

	.defines = client_auth_setting_defines,
	.defaults = &client_auth_default_settings,

	.pool_offset1 = 1 + offsetof(struct client_auth_settings, pool),
	.struct_size = sizeof(struct client_auth_settings),
};

const struct client_auth_settings *
client_auth_settings_ref(pool_t pool, const struct client_auth_settings *set)
{
	if (set->pool != NULL) {
		/* Proper persistent settings struct with a pool: just add
		   reference to the pool. */
		pool_ref(set->pool);
		return set;
	}

	/* Settings struct allocated temporarily (on stack and/or data stack):
	   Allocate a new struct on our pool, apply defaults and clone the
	   filled-in contents of the source. */

	struct client_auth_settings *set_new;

	set_new = p_new(pool, struct client_auth_settings, 1);
	*set_new = client_auth_default_settings;
	set_new->pool = pool;
	set_new->manual = TRUE;
	pool_ref(pool);

	if (set->mechanism != NULL && *set->mechanism != '\0')
		set_new->mechanism = p_strdup(pool, set->mechanism);

	if (set->authid != NULL && *set->authid != '\0')
		set_new->authid = p_strdup(pool, set->authid);
	if (set->authzid != NULL && *set->authzid != '\0')
		set_new->authzid = p_strdup(pool, set->authzid);
	if (set->password == NULL || *set->password != '\0')
		set_new->password = p_strdup(pool, set->password);

	return set_new;
}

int client_auth_settings_equal(struct event *event1, struct event *event2,
			       const char **error_r)
{
	const struct client_auth_settings *set1, *set2;
	int ret = 1;

	if (settings_get(event1, &client_auth_setting_parser_info, 0,
			 &set1, error_r) < 0)
		return -1;
	if (settings_get(event2, &client_auth_setting_parser_info, 0,
			 &set2, error_r) < 0) {
		settings_free(set1);
		return -1;
	}

	if (!settings_equal(&client_auth_setting_parser_info, set1, set2, NULL))
		ret = 0;

	if (ret > 0 && !array_is_empty(&set1->mechanisms)) {
		/* Compare also the per-mechanism settings. The mechanism lists
		   themselves are already known to be equal. */
		const char *mech_name;

		array_foreach_elem(&set1->mechanisms, mech_name) {
			const struct client_auth_settings *mech_set1;
			const struct client_auth_settings *mech_set2;

			if (settings_get_filter(event1,
					CLIENT_AUTH_SETTINGS_FILTER, mech_name,
					&client_auth_setting_parser_info, 0,
					&mech_set1, error_r) < 0) {
				ret = -1;
				break;
			}
			if (settings_get_filter(event2,
					CLIENT_AUTH_SETTINGS_FILTER, mech_name,
					&client_auth_setting_parser_info, 0,
					&mech_set2, error_r) < 0) {
				settings_free(mech_set1);
				ret = -1;
				break;
			}
			if (!settings_equal(&client_auth_setting_parser_info,
					    mech_set1, mech_set2, NULL))
				ret = 0;
			settings_free(mech_set1);
			settings_free(mech_set2);
			if (ret == 0)
				break;
		}
	}

	settings_free(set1);
	settings_free(set2);
	return ret;
}
