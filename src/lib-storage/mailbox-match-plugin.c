/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "wildcard-match.h"
#include "mail-storage-private.h"
#include "mailbox-match-plugin.h"

struct mailbox_match_plugin {
	ARRAY_TYPE(const_string) patterns;
};

struct mailbox_match_plugin *
mailbox_match_plugin_init(struct mail_user *user, const char *set_prefix)
{
	struct mailbox_match_plugin *match;
	string_t *str;
	const char *value;

	match = i_new(struct mailbox_match_plugin, 1);

	value = mail_user_plugin_getenv(user, set_prefix);
	if (value == NULL)
		return match;

	i_array_init(&match->patterns, 16);
	str = t_str_new(128);
	for (unsigned int i = 2; value != NULL; i++) {
		/* value points to user's settings, so there's no need to
		   strdup() it. */
		array_push_back(&match->patterns, &value);

		str_truncate(str, 0);
		str_printfa(str, "%s%u", set_prefix, i);

		value = mail_user_plugin_getenv(user, str_c(str));
	}

	return match;
}

bool mailbox_match_plugin_exclude(struct mailbox_match_plugin *match,
				  struct mailbox *box)
{
	const struct mailbox_settings *set;
	const char *const *special_use;
	const char *str;

	if (!array_is_created(&match->patterns))
		return FALSE;

	set = mailbox_settings_find(mailbox_get_namespace(box),
				    mailbox_get_vname(box));
	special_use = set == NULL ? NULL :
		t_strsplit_spaces(set->special_use, " ");

	array_foreach_elem(&match->patterns, str) {
		if (str[0] == '\\') {
			/* \Special-use flag */
			if (special_use != NULL &&
			    str_array_icase_find(special_use, str))
				return TRUE;
		} else {
			/* mailbox name with wildcards */
			if (wildcard_match(box->name, str))
				return TRUE;
		}
	}
	return FALSE;
}

void mailbox_match_plugin_deinit(struct mailbox_match_plugin **_match)
{
	struct mailbox_match_plugin *match = *_match;

	if (match == NULL)
		return;
	*_match = NULL;

	array_free(&match->patterns);
	i_free(match);
}
