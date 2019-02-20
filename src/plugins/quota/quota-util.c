/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "wildcard-match.h"
#include "quota-private.h"

#include <ctype.h>

#define QUOTA_DEFAULT_GRACE "10%"

#define RULE_NAME_DEFAULT_FORCE "*"
#define RULE_NAME_DEFAULT_NONFORCE "?"

struct quota_rule *
quota_root_rule_find(struct quota_root_settings *root_set, const char *name)
{
	struct quota_rule *rule;

	array_foreach_modifiable(&root_set->rules, rule) {
		if (wildcard_match(name, rule->mailbox_mask))
			return rule;
	}
	return NULL;
}

static struct quota_rule *
quota_root_rule_find_exact(struct quota_root_settings *root_set,
			   const char *name)
{
	struct quota_rule *rule;

	array_foreach_modifiable(&root_set->rules, rule) {
		if (strcmp(rule->mailbox_mask, name) == 0)
			return rule;
	}
	return NULL;
}

static int
quota_rule_parse_percentage(struct quota_root_settings *root_set,
			    struct quota_rule *rule,
			    int64_t *limit, const char **error_r)
{
	int64_t percentage = *limit;

	if (percentage <= -100 || percentage >= UINT_MAX) {
		*error_r = "Invalid percentage";
		return -1;
	}

	if (rule == &root_set->default_rule) {
		*error_r = "Default rule can't be a percentage";
		return -1;
	}

	if (limit == &rule->bytes_limit)
		rule->bytes_percent = percentage;
	else if (limit == &rule->count_limit)
		rule->count_percent = percentage;
	else
		i_unreached();
	return 0;
}

static int quota_limit_parse(struct quota_root_settings *root_set,
			     struct quota_rule *rule, const char *unit,
			     uint64_t multiply, int64_t *limit,
			     const char **error_r)
{
	switch (i_toupper(*unit)) {
	case '\0':
		/* default */
		break;
	case 'B':
		multiply = 1;
		break;
	case 'K':
		multiply = 1024;
		break;
	case 'M':
		multiply = 1024*1024;
		break;
	case 'G':
		multiply = 1024*1024*1024;
		break;
	case 'T':
		multiply = 1024ULL*1024*1024*1024;
		break;
	case '%':
		multiply = 0;
		if (quota_rule_parse_percentage(root_set, rule, limit,
						error_r) < 0)
			return -1;
		break;
	default:
		*error_r = t_strdup_printf("Unknown unit: %s", unit);
		return -1;
	}
	*limit *= multiply;
	return 0;
}

static void
quota_rule_recalculate_relative_rules(struct quota_rule *rule,
				      int64_t bytes_limit, int64_t count_limit)
{
	if (rule->bytes_percent != 0)
		rule->bytes_limit = bytes_limit * rule->bytes_percent / 100;
	if (rule->count_percent != 0)
		rule->count_limit = count_limit * rule->count_percent / 100;
}

void quota_root_recalculate_relative_rules(struct quota_root_settings *root_set,
					   int64_t bytes_limit,
					   int64_t count_limit)
{
	struct quota_rule *rule;
	struct quota_warning_rule *warning_rule;

	array_foreach_modifiable(&root_set->rules, rule) {
		quota_rule_recalculate_relative_rules(rule, bytes_limit,
						      count_limit);
	}

	array_foreach_modifiable(&root_set->warning_rules, warning_rule) {
		quota_rule_recalculate_relative_rules(&warning_rule->rule,
						      bytes_limit, count_limit);
	}
	quota_rule_recalculate_relative_rules(&root_set->grace_rule,
					      bytes_limit, 0);
	root_set->last_mail_max_extra_bytes = root_set->grace_rule.bytes_limit;

	if (root_set->set->debug && root_set->set->initialized) {
		i_debug("Quota root %s: Recalculated relative rules with "
			"bytes=%lld count=%lld. Now grace=%"PRIu64, root_set->name,
			(long long)bytes_limit, (long long)count_limit,
			root_set->last_mail_max_extra_bytes);
	}
}

static int
quota_rule_parse_limits(struct quota_root_settings *root_set,
			struct quota_rule *rule, const char *limits,
			const char *full_rule_def,
			bool relative_rule, const char **error_r)
{
	const char **args, *key, *value, *error, *p;
	uint64_t multiply;
	int64_t *limit;

	args = t_strsplit(limits, ":");
	for (; *args != NULL; args++) {
		multiply = 1;
		limit = NULL;

		key = *args;
		value = strchr(key, '=');
		if (value == NULL)
			value = "";
		else
			key = t_strdup_until(key, value++);

		if (*value == '+') {
			if (!relative_rule) {
				*error_r = "Rule limit cannot have '+'";
				return -1;
			}
			value++;
		} else if (*value != '-' && relative_rule) {
			i_warning("quota root %s rule %s: "
				  "obsolete configuration for rule '%s' "
				  "should be changed to '%s=+%s'",
				  root_set->name, full_rule_def,
				  *args, key, value);
		}

		if (strcmp(key, "storage") == 0) {
			multiply = 1024;
			limit = &rule->bytes_limit;
			if (str_parse_int64(value, limit, &p) < 0) {
				*error_r = p_strdup_printf(root_set->set->pool,
						"Invalid storage limit: %s", value);
				return -1;
			}
		} else if (strcmp(key, "bytes") == 0) {
			limit = &rule->bytes_limit;
			if (str_parse_int64(value, limit, &p) < 0) {
				*error_r = p_strdup_printf(root_set->set->pool,
						"Invalid bytes limit: %s", value);
				return -1;
			}
		} else if (strcmp(key, "messages") == 0) {
			limit = &rule->count_limit;
			if (str_parse_int64(value, limit, &p) < 0) {
				*error_r = p_strdup_printf(root_set->set->pool,
						"Invalid bytes messages: %s", value);
				return -1;
			}
		} else {
			*error_r = p_strdup_printf(root_set->set->pool,
					"Unknown rule limit name: %s", key);
			return -1;
		}

		if (quota_limit_parse(root_set, rule, p, multiply,
				      limit, &error) < 0) {
			*error_r = p_strdup_printf(root_set->set->pool,
				"Invalid rule limit value '%s': %s",
				*args, error);
			return -1;
		}
	}
	if (!relative_rule) {
		if (rule->bytes_limit < 0) {
			*error_r = "Bytes limit can't be negative";
			return -1;
		}
		if (rule->count_limit < 0) {
			*error_r = "Count limit can't be negative";
			return -1;
		}
	}
	return 0;
}

int quota_root_add_rule(struct quota_root_settings *root_set,
			const char *rule_def, const char **error_r)
{
	struct quota_rule *rule;
	const char *p, *mailbox_mask;
	int ret = 0;

	p = strchr(rule_def, ':');
	if (p == NULL) {
		*error_r = "Invalid rule";
		return -1;
	}

	/* <mailbox mask>:<quota limits> */
	mailbox_mask = t_strdup_until(rule_def, p++);

	rule = quota_root_rule_find_exact(root_set, mailbox_mask);
	if (rule == NULL) {
		if (strcmp(mailbox_mask, RULE_NAME_DEFAULT_NONFORCE) == 0)
			rule = &root_set->default_rule;
		else if (strcmp(mailbox_mask, RULE_NAME_DEFAULT_FORCE) == 0) {
			rule = &root_set->default_rule;
			root_set->force_default_rule = TRUE;
		} else {
			rule = array_append_space(&root_set->rules);
			rule->mailbox_mask = strcasecmp(mailbox_mask, "INBOX") == 0 ? "INBOX" :
				p_strdup(root_set->set->pool, mailbox_mask);
		}
	}

	if (strcmp(p, "ignore") == 0) {
		rule->ignore = TRUE;
		if (root_set->set->debug) {
			i_debug("Quota rule: root=%s mailbox=%s ignored",
				root_set->name, mailbox_mask);
		}
		return 0;
	}

	if (str_begins(p, "backend=")) {
		if (root_set->backend->v.parse_rule == NULL) {
			*error_r = "backend rule not supported";
			ret = -1;
		} else if (!root_set->backend->v.parse_rule(root_set, rule,
							    p + 8, error_r))
			ret = -1;
	} else {
		bool relative_rule = rule != &root_set->default_rule;

		if (quota_rule_parse_limits(root_set, rule, p, rule_def,
					    relative_rule, error_r) < 0)
			ret = -1;
	}

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		const char *rule_plus =
			rule == &root_set->default_rule ? "" : "+";

		i_debug("Quota rule: root=%s mailbox=%s "
			"bytes=%s%lld%s messages=%s%lld%s",
			root_set->name, mailbox_mask,
			rule->bytes_limit > 0 ? rule_plus : "",
			(long long)rule->bytes_limit,
			rule->bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->bytes_percent),
			rule->count_limit > 0 ? rule_plus : "",
			(long long)rule->count_limit,
			rule->count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", rule->count_percent));
	}
	return ret;
}

int quota_root_add_warning_rule(struct quota_root_settings *root_set,
				const char *rule_def, const char **error_r)
{
	struct quota_warning_rule *warning;
	struct quota_rule rule;
	const char *p, *q;
	int ret;
	bool reverse = FALSE;

	p = strchr(rule_def, ' ');
	if (p == NULL || p[1] == '\0') {
		*error_r = "No command specified";
		return -1;
	}

	if (*rule_def == '+') {
		/* warn when exceeding quota */
		q = rule_def+1;
	} else if (*rule_def == '-') {
		/* warn when going below quota */
		q = rule_def+1;
		reverse = TRUE;
	} else {
		/* default: same as '+' */
		q = rule_def;
	}

	i_zero(&rule);
	ret = quota_rule_parse_limits(root_set, &rule, t_strdup_until(q, p),
				      rule_def, FALSE, error_r);
	if (ret < 0)
		return -1;

	warning = array_append_space(&root_set->warning_rules);
	warning->command = p_strdup(root_set->set->pool, p+1);
	warning->rule = rule;
	warning->reverse = reverse;
	if (reverse)
		root_set->have_reverse_warnings = TRUE;

	quota_root_recalculate_relative_rules(root_set,
					      root_set->default_rule.bytes_limit,
					      root_set->default_rule.count_limit);
	if (root_set->set->debug) {
		i_debug("Quota warning: bytes=%"PRId64"%s "
			"messages=%"PRId64"%s reverse=%s command=%s",
			warning->rule.bytes_limit,
			warning->rule.bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.bytes_percent),
			warning->rule.count_limit,
			warning->rule.count_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", warning->rule.count_percent),
			warning->reverse ? "yes" : "no",
			warning->command);
	}
	return 0;
}

int quota_root_parse_grace(struct quota_root_settings *root_set,
			   const char *value, const char **error_r)
{
	const char *p;

	if (value == NULL) {
		/* default */
		value = QUOTA_DEFAULT_GRACE;
	}

	if (str_parse_int64(value, &root_set->grace_rule.bytes_limit, &p) < 0)
		return -1;
	if (quota_limit_parse(root_set, &root_set->grace_rule, p, 1,
			      &root_set->grace_rule.bytes_limit, error_r) < 0)
		return -1;
	quota_rule_recalculate_relative_rules(&root_set->grace_rule,
		root_set->default_rule.bytes_limit, 0);
	root_set->last_mail_max_extra_bytes = root_set->grace_rule.bytes_limit;
	if (root_set->set->debug) {
		i_debug("Quota grace: root=%s bytes=%lld%s",
			root_set->name, (long long)root_set->grace_rule.bytes_limit,
			root_set->grace_rule.bytes_percent == 0 ? "" :
			t_strdup_printf(" (%u%%)", root_set->grace_rule.bytes_percent));
	}
	return 0;
}

bool quota_warning_match(const struct quota_warning_rule *w,
			 uint64_t bytes_before, uint64_t bytes_current,
			 uint64_t count_before, uint64_t count_current,
			 const char **reason_r)
{
#define QUOTA_EXCEEDED(before, current, limit) \
	((before) < (uint64_t)(limit) && (current) >= (uint64_t)(limit))
	if (!w->reverse) {
		/* over quota (default) */
		if (QUOTA_EXCEEDED(bytes_before, bytes_current, w->rule.bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				bytes_before, bytes_current, w->rule.bytes_limit);
			return TRUE;
		}
		if (QUOTA_EXCEEDED(count_before, count_current, w->rule.count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" over limit %"PRId64,
				count_before, count_current, w->rule.count_limit);
			return TRUE;
		}
	} else {
		if (QUOTA_EXCEEDED(bytes_current, bytes_before, w->rule.bytes_limit)) {
			*reason_r = t_strdup_printf("bytes=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				bytes_before, bytes_current, w->rule.bytes_limit);
			return TRUE;
		}
		if (QUOTA_EXCEEDED(count_current, count_before, w->rule.count_limit)) {
			*reason_r = t_strdup_printf("count=%"PRIu64" -> %"PRIu64" below limit %"PRId64,
				count_before, count_current, w->rule.count_limit);
			return TRUE;
		}
	}
	return FALSE;
}

bool quota_transaction_is_over(struct quota_transaction_context *ctx,
			       uoff_t size)
{
	if (ctx->count_used < 0) {
		/* we've deleted some messages. we should be ok, unless we
		   were already over quota and still are after these
		   deletions. */
		const uint64_t count_deleted = (uint64_t)-ctx->count_used;

		if (ctx->count_over > 0) {
			if (count_deleted - 1 < ctx->count_over)
				return TRUE;
		}
	} else {
		if (ctx->count_ceil < 1 ||
		    ctx->count_ceil - 1 < (uint64_t)ctx->count_used) {
			/* count limit reached */
			return TRUE;
		}
	}

	if (ctx->bytes_used < 0) {
		const uint64_t bytes_deleted = (uint64_t)-ctx->bytes_used;

		/* we've deleted some messages. same logic as above. */
		if (ctx->bytes_over > 0) {
			if (ctx->bytes_over > bytes_deleted) {
				/* even after deletions we're over quota */
				return TRUE;
			}
			if (size > bytes_deleted - ctx->bytes_over)
				return TRUE;
		} else {
			if (size > bytes_deleted &&
			    size - bytes_deleted < ctx->bytes_ceil)
				return TRUE;
		}
	} else if (size == 0) {
		/* we need to explicitly test this case, since the generic
		   check would fail if user is already over quota */
		if (ctx->bytes_over > 0)
			return TRUE;
	} else {
		if (ctx->bytes_ceil < size ||
		    ctx->bytes_ceil - size < (uint64_t)ctx->bytes_used) {
			/* bytes limit reached */
			return TRUE;
		}
	}
	return FALSE;
}
