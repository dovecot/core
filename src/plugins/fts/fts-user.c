/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "str-parse.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "mailbox-match-plugin.h"
#include "language.h"
#include "lang-filter.h"
#include "lang-tokenizer.h"
#include "fts-user.h"
#include "settings.h"
#include "fts-settings.h"

#define FTS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_user_module)
#define FTS_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_user_module)

struct fts_user {
	union mail_user_module_context module_ctx;
	const struct fts_settings *set;
	int refcount;

	struct language_list *lang_list;
	struct fts_user_language *data_lang;
	ARRAY_TYPE(fts_user_language) languages, data_languages;

	struct mailbox_match_plugin *autoindex_exclude;

	size_t fts_message_max_size;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_user_module,
				  &mail_user_module_register);

static const char *const *str_keyvalues_to_array(const char *str)
{
	const char *key, *value, *const *keyvalues;
	ARRAY_TYPE(const_string) arr;
	unsigned int i;

	if (str == NULL)
		return NULL;

	t_array_init(&arr, 8);
	keyvalues = t_strsplit_spaces(str, " ");
	for (i = 0; keyvalues[i] != NULL; i++) {
		value = strchr(keyvalues[i], '=');
		if (value != NULL)
			key = t_strdup_until(keyvalues[i], value++);
		else {
			key = keyvalues[i];
			value = "";
		}
		array_push_back(&arr, &key);
		array_push_back(&arr, &value);
	}
	array_append_zero(&arr);
	return array_front(&arr);
}

static int
fts_user_init_languages(struct mail_user *user, struct fts_user *fuser,
			const char **error_r)
{
	const char *languages, *unknown;

	languages = mail_user_plugin_getenv(user, "fts_languages");
	if (languages == NULL) {
		*error_r = "fts_languages setting is missing";
		return -1;
	}

	struct language_settings lang_settings = {
		.textcat_config_path = mail_user_plugin_getenv(user, "fts_language_config")
	};
	fuser->lang_list = language_list_init(&lang_settings);

	if (!language_list_add_names(fuser->lang_list, languages, &unknown)) {
		*error_r = t_strdup_printf(
			"fts_languages: Unknown language '%s'", unknown);
		return -1;
	}
	if (array_count(language_list_get_all(fuser->lang_list)) == 0) {
		*error_r = "fts_languages setting is empty";
		return -1;
	}
	return 0;
}

static int
fts_user_create_filters(struct mail_user *user, const struct language *lang,
			struct lang_filter **filter_r, const char **error_r)
{
	const struct lang_filter *filter_class;
	struct lang_filter *filter = NULL, *parent = NULL;
	const char *filters_key, *const *filters, *filter_set_name;
	const char *str, *error, *set_key;
	unsigned int i;
	int ret = 0;

	/* try to get the language-specific filters first */
	filters_key = t_strconcat("fts_filters_", lang->name, NULL);
	str = mail_user_plugin_getenv(user, filters_key);
	if (str == NULL) {
		/* fallback to global filters */
		filters_key = "fts_filters";
		str = mail_user_plugin_getenv(user, filters_key);
		if (str == NULL) {
			/* No filters */
			*filter_r = NULL;
			return 0;
		}
	}

	filters = t_strsplit_spaces(str, " ");
	for (i = 0; filters[i] != NULL; i++) {
		filter_class = lang_filter_find(filters[i]);
		if (filter_class == NULL) {
			*error_r = t_strdup_printf("%s: Unknown filter '%s'",
						   filters_key, filters[i]);
			ret = -1;
			break;
		}

		/* try the language-specific setting first */
		filter_set_name = t_str_replace(filters[i], '-', '_');
		set_key = t_strdup_printf("fts_filter_%s_%s",
					  lang->name, filter_set_name);
		str = mail_user_plugin_getenv(user, set_key);
		if (str == NULL) {
			set_key = t_strdup_printf("fts_filter_%s", filter_set_name);
			str = mail_user_plugin_getenv(user, set_key);
		}

		if (lang_filter_create(filter_class, parent, lang,
				       str_keyvalues_to_array(str),
				       &filter, &error) < 0) {
			*error_r = t_strdup_printf("%s: %s", set_key, error);
			ret = -1;
			break;
		}
		if (parent != NULL)
			lang_filter_unref(&parent);
		parent = filter;
	}
	if (ret < 0) {
		if (parent != NULL)
			lang_filter_unref(&parent);
		return -1;
	}
	*filter_r = filter;
	return 0;
}

static int
fts_user_create_tokenizer(struct mail_user *user,
			  const struct language *lang,
			  struct lang_tokenizer **tokenizer_r, bool search,
			  const char **error_r)
{
	const struct lang_tokenizer *tokenizer_class;
	struct lang_tokenizer *tokenizer = NULL, *parent = NULL;
	const char *tokenizers_key, *const *tokenizers, *tokenizer_set_name;
	const char *str, *error, *set_key;
	unsigned int i;
	int ret = 0;

	tokenizers_key = t_strconcat("fts_tokenizers_", lang->name, NULL);
	str = mail_user_plugin_getenv(user, tokenizers_key);
	if (str == NULL) {
		str = mail_user_plugin_getenv(user, "fts_tokenizers");
		if (str == NULL) {
			*error_r = t_strdup_printf("%s or fts_tokenizers setting must exist", tokenizers_key);
			return -1;
		}
		tokenizers_key = "fts_tokenizers";
	}

	tokenizers = t_strsplit_spaces(str, " ");

	for (i = 0; tokenizers[i] != NULL; i++) {
		tokenizer_class = lang_tokenizer_find(tokenizers[i]);
		if (tokenizer_class == NULL) {
			*error_r = t_strdup_printf("%s: Unknown tokenizer '%s'",
						   tokenizers_key, tokenizers[i]);
			ret = -1;
			break;
		}

		tokenizer_set_name = t_str_replace(tokenizers[i], '-', '_');
		set_key = t_strdup_printf("fts_tokenizer_%s_%s", tokenizer_set_name, lang->name);
		str = mail_user_plugin_getenv(user, set_key);
		if (str == NULL) {
			set_key = t_strdup_printf("fts_tokenizer_%s", tokenizer_set_name);
			str = mail_user_plugin_getenv(user, set_key);
		}

		/* tell the tokenizers that we're tokenizing a search string
		   (instead of tokenizing indexed data) */
		if (search)
			str = t_strconcat("search=yes ", str, NULL);

		if (lang_tokenizer_create(tokenizer_class, parent,
					  str_keyvalues_to_array(str),
					  &tokenizer, &error) < 0) {
			*error_r = t_strdup_printf("%s: %s", set_key, error);
			ret = -1;
			break;
		}
		if (parent != NULL)
			lang_tokenizer_unref(&parent);
		parent = tokenizer;
	}
	if (ret < 0) {
		if (parent != NULL)
			lang_tokenizer_unref(&parent);
		return -1;
	}
	*tokenizer_r = tokenizer;
	return 0;
}

static int
fts_user_language_init_tokenizers(struct mail_user *user,
				  struct fts_user_language *user_lang,
				  const char **error_r)
{
	int ret;
	T_BEGIN {
		ret = fts_user_create_tokenizer(user, user_lang->lang,
						&user_lang->index_tokenizer,
						FALSE, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0)
		return -1;

	T_BEGIN {
		ret = fts_user_create_tokenizer(user, user_lang->lang,
						&user_lang->search_tokenizer,
						TRUE, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	return ret;
}

struct fts_user_language *
fts_user_language_find(struct mail_user *user,
		       const struct language *lang)
{
	struct fts_user_language *user_lang;
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);

	array_foreach_elem(&fuser->languages, user_lang) {
		if (strcmp(user_lang->lang->name, lang->name) == 0)
			return user_lang;
	}
	return NULL;
}

static int fts_user_language_create(struct mail_user *user,
                                    struct fts_user *fuser,
				    const struct language *lang,
				    const char **error_r)
{
	struct fts_user_language *user_lang;

	user_lang = p_new(user->pool, struct fts_user_language, 1);
	user_lang->lang = lang;
	array_push_back(&fuser->languages, &user_lang);

	if (fts_user_language_init_tokenizers(user, user_lang, error_r) < 0)
		return -1;
	if (fts_user_create_filters(user, lang, &user_lang->filter, error_r) < 0)
		return -1;
	return 0;
}

static int fts_user_languages_fill_all(struct mail_user *user,
                                       struct fts_user *fuser,
                                       const char **error_r)
{
	const struct language *lang;

	array_foreach_elem(language_list_get_all(fuser->lang_list), lang) {
		if (fts_user_language_create(user, fuser, lang, error_r) < 0)
			return -1;
	}
	return 0;
}

static int
fts_user_init_data_language(struct mail_user *user, struct fts_user *fuser,
			    const char **error_r)
{
	struct fts_user_language *user_lang;
	const char *error;

	user_lang = p_new(user->pool, struct fts_user_language, 1);
	user_lang->lang = &language_data;

	if (fts_user_language_init_tokenizers(user, user_lang, error_r) < 0)
		return -1;

	if (lang_filter_create(lang_filter_lowercase, NULL, user_lang->lang, NULL,
			       &user_lang->filter, &error) < 0)
		i_unreached();
	i_assert(user_lang->filter != NULL);

	p_array_init(&fuser->data_languages, user->pool, 1);
	array_push_back(&fuser->data_languages, &user_lang);
	array_push_back(&fuser->languages, &user_lang);

	fuser->data_lang = user_lang;
	return 0;
}

struct language_list *fts_user_get_language_list(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);

	return fuser->lang_list;
}

const ARRAY_TYPE(fts_user_language) *
fts_user_get_all_languages(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);

	return &fuser->languages;
}

const ARRAY_TYPE(fts_user_language) *
fts_user_get_data_languages(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);

	return &fuser->data_languages;
}

struct fts_user_language *fts_user_get_data_lang(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);

	return fuser->data_lang;
}

const struct fts_settings *fts_user_get_settings(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);
	return fuser->set;
}

bool fts_user_autoindex_exclude(struct mailbox *box)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(box->storage->user);

	return mailbox_match_plugin_exclude(fuser->autoindex_exclude, box);
}

static void fts_user_language_free(struct fts_user_language *user_lang)
{
	if (user_lang->filter != NULL)
		lang_filter_unref(&user_lang->filter);
	if (user_lang->index_tokenizer != NULL)
		lang_tokenizer_unref(&user_lang->index_tokenizer);
	if (user_lang->search_tokenizer != NULL)
		lang_tokenizer_unref(&user_lang->search_tokenizer);
}

static void fts_user_free(struct fts_user *fuser)
{
	struct fts_user_language *user_lang;

	if (fuser->lang_list != NULL)
		language_list_deinit(&fuser->lang_list);

	if (array_is_created(&fuser->languages)) {
		array_foreach_elem(&fuser->languages, user_lang)
			fts_user_language_free(user_lang);
	}

	settings_free(fuser->set);
}

static int
fts_mail_user_init_libfts(struct mail_user *user, struct fts_user *fuser,
			  const char **error_r)
{
	p_array_init(&fuser->languages, user->pool, 4);

	if (fts_user_init_languages(user, fuser, error_r) < 0 ||
	    fts_user_init_data_language(user, fuser, error_r) < 0)
		return -1;
	if (fts_user_languages_fill_all(user, fuser, error_r) < 0)
		return -1;
	return 0;
}

size_t fts_mail_user_message_max_size(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT_REQUIRE(user);
	return fuser->fts_message_max_size;
}

int fts_mail_user_init(struct mail_user *user, bool initialize_libfts,
		       const char **error_r)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	if (fuser != NULL) {
		/* multiple fts plugins are loaded */
		fuser->refcount++;
		return 0;
	}

	const char *error;
	const struct fts_settings *set;
	if (settings_get(user->event, &fts_setting_parser_info, 0, &set, &error) < 0) {
		e_error(user->event, "%s", error);
		return -1;
	}

	fuser = p_new(user->pool, struct fts_user, 1);
	fuser->set = set;
	fuser->refcount = 1;
	if (initialize_libfts) {
		if (fts_mail_user_init_libfts(user, fuser, error_r) < 0) {
			fts_user_free(fuser);
			return -1;
		}
	}
	fuser->autoindex_exclude =
		mailbox_match_plugin_init(user, "fts_autoindex_exclude");

	const char *fts_max_size_setting =
		mail_user_plugin_getenv(user, "fts_message_max_size");

	if (fts_max_size_setting != NULL) {
		const char *error;
		if (str_parse_get_size(fts_max_size_setting,
				       &fuser->fts_message_max_size, &error) < 0) {
			*error_r = t_strdup_printf("Cannot parse fts_message_max_size: %s", error);
			fts_user_free(fuser);
			return -1;
		}
	}

	MODULE_CONTEXT_SET(user, fts_user_module, fuser);
	return 0;
}

void fts_mail_user_deinit(struct mail_user *user)
{
	struct fts_user *fuser = FTS_USER_CONTEXT(user);

	if (fuser != NULL) {
		i_assert(fuser->refcount > 0);
		if (--fuser->refcount == 0)
			fts_user_free(fuser);
	}
}
