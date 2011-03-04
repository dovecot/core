/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-search.h"
#include "mail-search-register.h"

struct mail_search_register {
	ARRAY_DEFINE(args, struct mail_search_register_arg);
	mail_search_register_fallback_t *fallback;

	unsigned int args_sorted:1;
};

struct mail_search_register *mail_search_register_init(void)
{
	struct mail_search_register *reg;

	reg = i_new(struct mail_search_register, 1);
	i_array_init(&reg->args, 64);
	return reg;
}

void mail_search_register_deinit(struct mail_search_register **_reg)
{
	struct mail_search_register *reg = *_reg;

	*_reg = NULL;

	array_free(&reg->args);
	i_free(reg);
}

void mail_search_register_add(struct mail_search_register *reg,
			      const struct mail_search_register_arg *arg,
			      unsigned int count)
{
	array_append(&reg->args, arg, count);
	reg->args_sorted = FALSE;
}

void mail_search_register_fallback(struct mail_search_register *reg,
				   mail_search_register_fallback_t *fallback)
{
	reg->fallback = fallback;
}

static int
mail_search_register_arg_cmp(const struct mail_search_register_arg *arg1,
			     const struct mail_search_register_arg *arg2)
{
	return strcmp(arg1->key, arg2->key);
}

const struct mail_search_register_arg *
mail_search_register_get(struct mail_search_register *reg,
			 unsigned int *count_r)
{
	if (!reg->args_sorted) {
		array_sort(&reg->args, mail_search_register_arg_cmp);
		reg->args_sorted = TRUE;
	}

	return array_get(&reg->args, count_r);
}

const struct mail_search_register_arg *
mail_search_register_find(struct mail_search_register *reg, const char *key)
{
	struct mail_search_register_arg arg;

	if (!reg->args_sorted) {
		array_sort(&reg->args, mail_search_register_arg_cmp);
		reg->args_sorted = TRUE;
	}

	arg.key = key;
	return array_bsearch(&reg->args, &arg, mail_search_register_arg_cmp);
}

bool mail_search_register_get_fallback(struct mail_search_register *reg,
				       mail_search_register_fallback_t **fallback_r)
{
	if (reg->fallback == NULL)
		return FALSE;

	*fallback_r = reg->fallback;
	return TRUE;
}
