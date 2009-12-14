/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "settings-parser.h"
#include "imap-match.h"
#include "mail-namespace.h"
#include "expire-env.h"

#include <stdlib.h>

enum expire_type {
	EXPIRE_TYPE_EXPUNGE,
	EXPIRE_TYPE_ALTMOVE
};

struct expire_rule {
	const char *pattern;
	struct imap_match_glob *glob;

	enum expire_type type;
	unsigned int expire_secs;
};

struct expire_env {
	pool_t pool;
	ARRAY_DEFINE(rules, struct expire_rule);
};

static void
expire_env_parse(struct expire_env *env, struct mail_namespace *namespaces,
		 const char *str)
{
	struct expire_rule rule;
	struct mail_namespace *ns;
	const char *const *args;
	const char *p, *ns_name, *type_str, *error;

	if (*str == '"') {
		/* quoted string */
		for (p = ++str; *p != '\0'; p++) {
			if (*p == '\\' && p[1] != '\0')
				p++;
			else if (*p == '"')
				break;
		}
		rule.pattern = str_unescape(p_strdup_until(env->pool, str, p));
		if (*p == '"') p++;
	} else {
		p = strchr(str, ' ');
		if (p == NULL) p = str + strlen(str);
		rule.pattern = p_strdup_until(env->pool, str, p);
	}

	if (*p == ' ') p++;
	args = t_strsplit_spaces(p, " ");

	/* find namespace's separator and create a glob */
	ns_name = rule.pattern;
	ns = mail_namespace_find(namespaces, &ns_name);
	if (ns == NULL && *rule.pattern != '*') {
		i_warning("expire: No namespace found for mailbox: %s",
			  rule.pattern);
	}
	rule.glob = imap_match_init(env->pool, rule.pattern, TRUE,
				    ns == NULL ? '/' : ns->sep);

	/* get expire time */
	if (args[0] == NULL) {
		i_fatal("expire: Missing expire time for mailbox '%s'",
			rule.pattern);
	}
	if (is_numeric(args[0], '\0')) {
		i_fatal("expire: Missing expire time specifier for mailbox "
			"'%s': %s (add e.g. 'days')", rule.pattern, args[0]);
	}
	if (settings_get_time(args[0], &rule.expire_secs, &error) < 0) {
		i_fatal("expire: Invalid time for mailbox '%s': %s",
			rule.pattern, error);
	}

	/* expire type */
	type_str = args[1] != NULL ? args[1] : "expunge";
	if (strcmp(type_str, "expunge") == 0)
		rule.type = EXPIRE_TYPE_EXPUNGE;
	else if (strcmp(type_str, "altmove") == 0)
		rule.type = EXPIRE_TYPE_ALTMOVE;
	else {
		i_fatal("expire: Unknown type for mailbox '%s': %s",
			rule.pattern, type_str);
	}

	if (namespaces->user->mail_debug) {
		i_debug("expire: pattern=%s secs=%u type=%s",
			rule.pattern, rule.expire_secs, type_str);
	}
	array_append(&env->rules, &rule, 1);
}

struct expire_env *expire_env_init(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct expire_env *env;
	const char *rule_str;
	char env_name[20];
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("Expire pool", 512);
	env = p_new(pool, struct expire_env, 1);
	env->pool = pool;
	p_array_init(&env->rules, env->pool, 16);

	rule_str = mail_user_set_plugin_getenv(user->set, "expire");
	for (i = 2; rule_str != NULL; i++) {
		expire_env_parse(env, namespaces, rule_str);

		i_snprintf(env_name, sizeof(env_name), "expire%u", i);
		rule_str = mail_user_set_plugin_getenv(user->set, env_name);
	}
	return env;
}

void expire_env_deinit(struct expire_env **_env)
{
	struct expire_env *env = *_env;

	*_env = NULL;
	pool_unref(&env->pool);
}

bool expire_rule_find(struct expire_env *env, const char *name,
		      unsigned int *expunge_secs_r,
		      unsigned int *altmove_secs_r)
{
	const struct expire_rule *rule;
	unsigned int secs, expunge_min = 0, altmove_min = 0;

	array_foreach(&env->rules, rule) {
		if (imap_match(rule->glob, name) == IMAP_MATCH_YES) {
			secs = rule->expire_secs;
			i_assert(secs > 0);

			switch (rule->type) {
			case EXPIRE_TYPE_EXPUNGE:
				if (expunge_min == 0 || expunge_min > secs)
					expunge_min = secs;
				break;
			case EXPIRE_TYPE_ALTMOVE:
				if (altmove_min == 0 || altmove_min > secs)
					altmove_min = secs;
				break;
			}
		}
	}
	*expunge_secs_r = expunge_min;
	*altmove_secs_r = altmove_min;
	return expunge_min > 0 || altmove_min > 0;
}

unsigned int expire_rule_find_min_secs(struct expire_env *env, const char *name,
				       bool *altmove_r)
{
	unsigned int secs1, secs2;

	(void)expire_rule_find(env, name, &secs1, &secs2);
	if (secs1 != 0 && (secs1 < secs2 || secs2 == 0)) {
		*altmove_r = FALSE;
		return secs1;
	} else {
		*altmove_r = TRUE;
		return secs2;
	}
}
