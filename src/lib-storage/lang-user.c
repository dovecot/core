/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "language.h"
#include "lang-filter.h"
#include "lang-tokenizer.h"
#include "lang-user.h"
#include "settings.h"
#include "lang-settings.h"

#define LANG_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lang_user_module)
#define LANG_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lang_user_module)

struct lang_user {
	union mail_user_module_context module_ctx;
	const struct langs_settings *set;
	int refcount;

	struct event *event;
	struct language_list *lang_list;
	struct language_user *data_lang;
	ARRAY_TYPE(language_user) languages, data_languages;
};

static MODULE_CONTEXT_DEFINE_INIT(lang_user_module,
				  &mail_user_module_register);

/* Returns the setting for the given language, or, if the langauge is not
   defined, the settings for the default language (which is always the first
   in the array) */
static const struct lang_settings *
lang_user_settings_get(struct mail_user *user, const char *lang)
{
	struct lang_settings *set;
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);
	const ARRAY_TYPE(lang_settings) *langs = &luser->set->parsed_languages;

	array_foreach_elem(langs, set) {
		if (strcmp(set->name, lang) == 0)
			return set;
	}

	i_assert(!(array_is_empty(langs)));
	return array_idx_elem(langs, 0);
}

static int
lang_user_init_languages(struct lang_user *luser, const char **error_r)
{
	const ARRAY_TYPE(lang_settings) *langs = &luser->set->parsed_languages;
	i_assert(!array_is_empty(langs));

	struct language_settings lang_settings = {
		.textcat_config_path = luser->set->textcat_config_path,
	};
	luser->lang_list = language_list_init(&lang_settings);

	const char *unknown_lang;
	if (!language_list_add_names(luser->lang_list, langs, &unknown_lang)) {
		*error_r = t_strdup_printf(
			"language %s: Unknown language", unknown_lang);
		return -1;
	}

	i_assert(!array_is_empty(language_list_get_all(luser->lang_list)));
	return 0;
}

static int
lang_user_create_filters(struct mail_user *user, const struct language *lang,
			 struct lang_filter **filter_r, const char **error_r)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);
	const struct lang_settings *set = lang_user_settings_get(user, lang->name);
	if (array_is_empty(&set->filters)) {
		/* No filters */
		*filter_r = NULL;
		return 0;
	}

	int ret = 0;
	struct lang_filter *filter = NULL, *parent = NULL;
	const char *entry_name;
	array_foreach_elem(&set->filters, entry_name) {
		const struct lang_filter *entry_class =
			lang_filter_find(entry_name);

		if (entry_class == NULL) {
			*error_r = t_strdup_printf(
				"%s: Unknown filter '%s'",
				set->name, entry_name);
			ret = -1;
			break;
		}

		const char *error;
		struct event *event = event_create(luser->event);
		event_add_str(event, "language", lang->name);
		ret = lang_filter_create(entry_class, parent, set, event,
					 &filter, &error);
		event_unref(&event);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"%s:%s %s", set->name, entry_name, error);
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
lang_user_create_tokenizer(struct mail_user *user, const struct language *lang,
			   struct lang_tokenizer **tokenizer_r, bool search,
			   const char **error_r)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);
	const struct lang_settings *set = lang_user_settings_get(user, lang->name);
	if (array_is_empty(&set->tokenizers)) {
		/* No tokenizers */
		*error_r = "Empty language_tokenizers { .. } list";
		return -1;
	}

	int ret = 0;
	struct lang_tokenizer *tokenizer = NULL, *parent = NULL;
	const char *entry_name;
	array_foreach_elem(&set->tokenizers, entry_name) {
		const struct lang_tokenizer *entry_class =
			lang_tokenizer_find(entry_name);

		if (entry_class == NULL) {
			*error_r = t_strdup_printf(
				"%s: Unknown tokenizer '%s'",
				set->name, entry_name);
			ret = -1;
			break;
		}

		const char *error;
		struct event *event = event_create(luser->event);
		event_add_str(event, "language", set->name);
		ret = lang_tokenizer_create(entry_class, parent, set, event,
					    search ? LANG_TOKENIZER_FLAG_SEARCH : 0,
					    &tokenizer, &error);
		event_unref(&event);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"%s:%s %s", set->name, entry_name, error);
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
lang_user_language_init_tokenizers(struct mail_user *user,
				   struct language_user *user_lang,
				   const char **error_r)
{
	int ret;
	T_BEGIN {
		ret = lang_user_create_tokenizer(user, user_lang->lang,
						 &user_lang->index_tokenizer,
						 FALSE, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0)
		return -1;

	T_BEGIN {
		ret = lang_user_create_tokenizer(user, user_lang->lang,
						 &user_lang->search_tokenizer,
						 TRUE, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	return ret;
}

struct language_user *
lang_user_language_find(struct mail_user *user,
		        const struct language *lang)
{
	struct language_user *user_lang;
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);

	array_foreach_elem(&luser->languages, user_lang) {
		if (strcmp(user_lang->lang->name, lang->name) == 0)
			return user_lang;
	}
	return NULL;
}

static int lang_user_language_create(struct mail_user *user,
                                     struct lang_user *luser,
				     const struct language *lang,
				     const char **error_r)
{
	struct language_user *user_lang;

	user_lang = p_new(user->pool, struct language_user, 1);
	user_lang->lang = lang;
	array_push_back(&luser->languages, &user_lang);

	if (lang_user_language_init_tokenizers(user, user_lang, error_r) < 0 ||
	    lang_user_create_filters(user, lang, &user_lang->filter, error_r) < 0)
		return -1;
	return 0;
}

static int lang_user_languages_fill_all(struct mail_user *user,
                                        struct lang_user *luser,
                                        const char **error_r)
{
	const struct language *lang;
	const char *error;

	array_foreach_elem(language_list_get_all(luser->lang_list), lang) {
		if (lang_user_language_create(user, luser, lang, &error) < 0) {
			*error_r = t_strdup_printf("language %s: %s",
						   lang->name, error);
			return -1;
		}
	}
	return 0;
}

static int
lang_user_init_data_language(struct mail_user *user, struct lang_user *luser,
			     const char **error_r)
{
	struct language_user *user_lang;
	const char *error;

	user_lang = p_new(user->pool, struct language_user, 1);
	user_lang->lang = &language_data;
	const struct lang_settings *set = lang_user_settings_get(user, language_data.name);

	if (lang_user_language_init_tokenizers(user, user_lang, &error) < 0) {
		*error_r = t_strdup_printf("language %s: %s",
					   user_lang->lang->name, error);
		return -1;
	}

	struct event *event = event_create(luser->event);
	event_add_str(event, "language", language_data.name);
	if (lang_filter_create(lang_filter_lowercase, NULL, set, event,
			       &user_lang->filter, &error) < 0)
		i_unreached();
	event_unref(&event);

	p_array_init(&luser->data_languages, user->pool, 1);
	array_push_back(&luser->data_languages, &user_lang);
	array_push_back(&luser->languages, &user_lang);

	luser->data_lang = user_lang;
	return 0;
}

struct language_list *lang_user_get_language_list(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);

	return luser->lang_list;
}

const ARRAY_TYPE(language_user) *
lang_user_get_all_languages(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);

	return &luser->languages;
}

const ARRAY_TYPE(language_user) *
lang_user_get_data_languages(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);

	return &luser->data_languages;
}

struct language_user *lang_user_get_data_lang(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);

	return luser->data_lang;
}

const struct langs_settings *lang_user_get_settings(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT_REQUIRE(user);
	return luser->set;
}

static void lang_user_language_free(struct language_user *user_lang)
{
	if (user_lang->filter != NULL)
		lang_filter_unref(&user_lang->filter);
	if (user_lang->index_tokenizer != NULL)
		lang_tokenizer_unref(&user_lang->index_tokenizer);
	if (user_lang->search_tokenizer != NULL)
		lang_tokenizer_unref(&user_lang->search_tokenizer);
}

static void lang_user_free(struct lang_user *luser)
{
	struct language_user *user_lang;

	if (luser->lang_list != NULL)
		language_list_deinit(&luser->lang_list);

	if (array_is_created(&luser->languages)) {
		array_foreach_elem(&luser->languages, user_lang)
			lang_user_language_free(user_lang);
	}

	settings_free(luser->set);
	event_unref(&luser->event);
}

static int
lang_user_init_libfts(struct mail_user *user, struct lang_user *luser,
		      const char **error_r)
{
	p_array_init(&luser->languages, user->pool, 4);

	if (lang_user_init_languages(luser, error_r) < 0 ||
	    lang_user_init_data_language(user, luser, error_r) < 0 ||
	    lang_user_languages_fill_all(user, luser, error_r) < 0)
		return -1;
	return 0;
}

int lang_user_init(struct mail_user *user, struct event *event,
		   bool initialize_libfts, const char **error_r)
{
	struct lang_user *luser = LANG_USER_CONTEXT(user);

	if (luser != NULL) {
		/* language user confs loaded multiple times */
		luser->refcount++;
		return 0;
	}

	const struct langs_settings *set;
	if (settings_get(event, &langs_setting_parser_info, 0, &set, error_r) < 0)
		return -1;

	luser = p_new(user->pool, struct lang_user, 1);
	luser->set = set;
	luser->refcount = 1;
	luser->event = event;
	event_ref(luser->event);

	MODULE_CONTEXT_SET(user, lang_user_module, luser);
	if (initialize_libfts) {
		if (lang_user_init_libfts(user, luser, error_r) < 0) {
			MODULE_CONTEXT_UNSET(user, lang_user_module);
			lang_user_free(luser);
			return -1;
		}
	}
	return 0;
}

void lang_user_deinit(struct mail_user *user)
{
	struct lang_user *luser = LANG_USER_CONTEXT(user);

	if (luser != NULL) {
		i_assert(luser->refcount > 0);
		if (--luser->refcount == 0)
			lang_user_free(luser);
	}
}
