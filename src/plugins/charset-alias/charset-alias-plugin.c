/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "charset-utf8-private.h"
#include "charset-alias-plugin.h"


#define CHARSET_ALIAS_USER_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, charset_alias_user_module)

static MODULE_CONTEXT_DEFINE_INIT(charset_alias_user_module,
				  &mail_user_module_register);

const char *charset_alias_plugin_version = DOVECOT_ABI_VERSION;

static int charset_alias_to_utf8_begin(const char *charset,
				       normalizer_func_t *normalizer,
				       struct charset_translation **t_r);

static void charset_alias_to_utf8_end(struct charset_translation *t);

static void charset_alias_to_utf8_reset(struct charset_translation *t);

static enum charset_result charset_alias_to_utf8(struct charset_translation *t,
						 const unsigned char *src,
						 size_t *src_size, buffer_t *dest);

/* charset_utf8_vfuncs is defined in lib-charset/charset-utf8.c */
extern const struct charset_utf8_vfuncs *charset_utf8_vfuncs;

static const struct charset_utf8_vfuncs *original_charset_utf8_vfuncs;

static const struct charset_utf8_vfuncs charset_alias_utf8_vfuncs = {
	charset_alias_to_utf8_begin,
	charset_alias_to_utf8_end,
	charset_alias_to_utf8_reset,
	charset_alias_to_utf8
};

struct charset_alias {
	const char *charset;
	const char *alias;
};

static ARRAY(struct charset_alias) charset_aliases;
static pool_t charset_alias_pool;
static int charset_alias_user_refcount = 0;

struct charset_alias_user {
	union mail_user_module_context module_ctx;
};


static const char *charset_alias_get_alias(const char *charset)
{
	const struct charset_alias* elem;
	const char *key;

	if (array_is_created(&charset_aliases)) {
		key = t_str_lcase(charset);
		array_foreach(&charset_aliases, elem) {
			if (strcmp(key, elem->charset) == 0) {
				return elem->alias;
			}
		}
	}
	return charset;
}

static int charset_alias_to_utf8_begin(const char *charset,
				       normalizer_func_t *normalizer,
				       struct charset_translation **t_r)
{
	i_assert(original_charset_utf8_vfuncs != NULL);
	charset = charset_alias_get_alias(charset);
	return original_charset_utf8_vfuncs->to_utf8_begin(charset, normalizer, t_r);
}
static void charset_alias_to_utf8_end(struct charset_translation *t)
{
	i_assert(original_charset_utf8_vfuncs != NULL);
	original_charset_utf8_vfuncs->to_utf8_end(t);
}

static void charset_alias_to_utf8_reset(struct charset_translation *t)
{
	i_assert(original_charset_utf8_vfuncs != NULL);
	original_charset_utf8_vfuncs->to_utf8_reset(t);
}

static enum charset_result charset_alias_to_utf8(struct charset_translation *t,
						 const unsigned char *src,
						 size_t *src_size, buffer_t *dest)
{
	i_assert(original_charset_utf8_vfuncs != NULL);
	return original_charset_utf8_vfuncs->to_utf8(t, src, src_size, dest);
}

static unsigned int charset_aliases_init(struct mail_user *user, pool_t pool, const char *str)
{
	const char *key, *value, *const *keyvalues;
	struct charset_alias alias;
	int i;

	i_assert(!array_is_created(&charset_aliases));

	p_array_init(&charset_aliases, pool, 1);
	keyvalues = t_strsplit_spaces(str, " ");
	for (i = 0; keyvalues[i] != NULL; i++) {
		value = strchr(keyvalues[i], '=');
		if (value == NULL) {
			i_error("charset_alias: Missing '=' in charset_aliases setting");
			continue;
		}
		key = t_strdup_until(keyvalues[i], value++);
		if (key[0] == '\0' || value[0] == '\0') {
			i_error("charset_alias: charset or alias missing in charset_aliases setting");
			continue;
		}
		if (strcasecmp(key, value) != 0) {
			e_debug(user->event, "charset_alias: add charset-alias %s for %s", value, key);
			alias.charset = p_strdup(pool, t_str_lcase(key));
			alias.alias = p_strdup(pool, value);
			array_append(&charset_aliases, &alias, 1);
		}
	}
	return array_count(&charset_aliases);
}

static void charset_alias_utf8_vfuncs_set(void)
{
	original_charset_utf8_vfuncs = charset_utf8_vfuncs;
	charset_utf8_vfuncs = &charset_alias_utf8_vfuncs;
}

static void charset_alias_utf8_vfuncs_reset(void)
{
	if (original_charset_utf8_vfuncs != NULL) {
		charset_utf8_vfuncs = original_charset_utf8_vfuncs;
		original_charset_utf8_vfuncs = NULL;
	}
}

static void charset_alias_mail_user_deinit(struct mail_user *user)
{
	struct charset_alias_user *cuser = CHARSET_ALIAS_USER_CONTEXT(user);

	i_assert(charset_alias_user_refcount > 0);
	if (--charset_alias_user_refcount == 0) {
		charset_alias_utf8_vfuncs_reset();
		array_free(&charset_aliases);
		pool_unref(&charset_alias_pool);
	}

	cuser->module_ctx.super.deinit(user);
}

static void charset_alias_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct charset_alias_user *cuser;
	const char *str;

	cuser = p_new(user->pool, struct charset_alias_user, 1);
	cuser->module_ctx.super = *v;
	user->vlast = &cuser->module_ctx.super;
	v->deinit = charset_alias_mail_user_deinit;

	if (charset_alias_user_refcount++ == 0) {
		charset_alias_pool = pool_alloconly_create("charset_alias alias list", 128);
		str = mail_user_plugin_getenv(user, "charset_aliases");
		if (str != NULL && str[0] != '\0') {
			if (charset_aliases_init(user, charset_alias_pool, str) > 0) {
				charset_alias_utf8_vfuncs_set();
			}
		}
	}

	MODULE_CONTEXT_SET(user, charset_alias_user_module, cuser);
}

static struct mail_storage_hooks charset_alias_mail_storage_hooks = {
	.mail_user_created = charset_alias_mail_user_created
};

void charset_alias_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &charset_alias_mail_storage_hooks);
}

void charset_alias_plugin_deinit(void)
{
	mail_storage_hooks_remove(&charset_alias_mail_storage_hooks);
}
