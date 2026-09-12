#ifndef CLIENT_AUTH_SETTINGS_H
#define CLIENT_AUTH_SETTINGS_H

#include "array.h"

#define CLIENT_AUTH_SETTINGS_FILTER "client_auth"

struct client_auth_settings {
	pool_t pool;

	/* Name of the SASL mechanism */
	const char *mechanism;

	/* authentication ID - must be set with most mechanisms */
	const char *authid;
	/* authorization ID (who to log in as, if authentication ID is a
	   master user) */
	const char *authzid;
	/* password - must be set with most mechanisms */
	const char *password;

	ARRAY_TYPE(const_string) mechanisms;

	/* Settings struct was created manually */
	bool manual;
};

extern const struct setting_parser_info client_auth_setting_parser_info;

/* Reference the provided settings struct, even when it is a struct on the call
   stack without a pool, in which case it is cloned to our pool. In both cases,
   the result can be dereferenced using settings_free(). */
const struct client_auth_settings *
client_auth_settings_ref(pool_t pool, const struct client_auth_settings *set);

/* Compares the client auth settings, including the per-mechanism settings, of
   the two events. Returns 1 if they are equal, 0 if they are not and -1 if
   looking up the settings failed. */
int client_auth_settings_equal(struct event *event1, struct event *event2,
			       const char **error_r);

static inline bool
client_auth_settings_mechanism_configured(const struct client_auth_settings *set)
{
	return (!array_is_empty(&set->mechanisms) ||
		(set->mechanism != NULL && *set->mechanism != '\0'));
}

#endif
