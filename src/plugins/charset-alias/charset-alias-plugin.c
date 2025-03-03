/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "settings.h"
#include "settings-parser.h"
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

struct charset_alias_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) charset_aliases;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct charset_alias_settings)
static const struct setting_define charset_alias_setting_defines[] = {
	DEF(STRLIST, charset_aliases),

	SETTING_DEFINE_LIST_END
};
static const struct charset_alias_settings charset_alias_default_settings = {
	.charset_aliases = ARRAY_INIT,
};

const struct setting_parser_info charset_alias_setting_parser_info = {
	.name = "charset_alias",
	.plugin_dependency = "lib20_charset_alias_plugin",

	.defines = charset_alias_setting_defines,
	.defaults = &charset_alias_default_settings,

	.struct_size = sizeof(struct charset_alias_settings),
	.pool_offset1 = 1 + offsetof(struct charset_alias_settings, pool),
};

static const struct charset_alias_settings *charset_alias_set;
static int charset_alias_user_refcount = 0;

struct charset_alias_user {
	union mail_user_module_context module_ctx;
};


static const char *charset_alias_get_alias(const char *charset)
{
	const char *const *str;
	unsigned int i, count;

	if (!array_is_created(&charset_alias_set->charset_aliases))
		return charset;

	str = array_get(&charset_alias_set->charset_aliases, &count);
	i_assert(count % 2 == 0);
	for (i = 0; i < count; i += 2) {
		if (strcasecmp(charset, str[i]) == 0)
			return str[i + 1];
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
		settings_free(charset_alias_set);
	}

	cuser->module_ctx.super.deinit(user);
}

static void charset_alias_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct charset_alias_user *cuser;
	const char *error;

	cuser = p_new(user->pool, struct charset_alias_user, 1);
	cuser->module_ctx.super = *v;
	user->vlast = &cuser->module_ctx.super;
	v->deinit = charset_alias_mail_user_deinit;

	if (charset_alias_user_refcount++ == 0) {
		if (settings_get(user->event,
				 &charset_alias_setting_parser_info, 0,
				 &charset_alias_set, &error) < 0) {
			user->error = p_strdup(user->pool, error);
			return;
		}

		if (!array_is_empty(&charset_alias_set->charset_aliases))
			charset_alias_utf8_vfuncs_set();
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
