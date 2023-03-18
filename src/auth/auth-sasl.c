/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth.h"
#include "auth-common.h"
#include "auth-sasl.h"

/*
 * Mechanisms
 */

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

static struct mech_module_list *mech_modules;

void mech_register_module(const struct mech_module *module)
{
	struct mech_module_list *list;
	i_assert(strcmp(module->mech_name, t_str_ucase(module->mech_name)) == 0);

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(const struct mech_module *module)
{
	struct mech_module_list **pos, *list;

	for (pos = &mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if (strcmp((*pos)->module.mech_name, module->mech_name) == 0) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

const struct mech_module *mech_module_find(const char *name)
{
	struct mech_module_list *list;
	name = t_str_ucase(name);

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}
