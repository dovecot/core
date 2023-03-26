/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "llist.h"

#include "sasl-server-private.h"

/*
 * Accessors
 */

const char *sasl_server_mech_get_name(const struct sasl_server_mech *mech)
{
	return mech->def->name;
}

enum sasl_mech_security_flags
sasl_server_mech_get_security_flags(const struct sasl_server_mech *mech)
{
	return mech->def->flags;
}

enum sasl_mech_passdb_need
sasl_server_mech_get_passdb_need(const struct sasl_server_mech *mech)
{
	return mech->def->passdb_need;
}

/*
 * Common functions
 */

void sasl_server_mech_generic_auth_initial(
	struct sasl_server_mech_request *mreq,
	const unsigned char *data, size_t data_size)
{
	const struct sasl_server_mech_def *mech = mreq->mech;

	if (data == NULL) {
		sasl_server_request_output(mreq, uchar_empty_ptr, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		i_assert(mech->funcs->auth_continue != NULL);
		mech->funcs->auth_continue(mreq, data, data_size);
	}
}

/*
 * Registry
 */

static struct sasl_server_mech_def_reg *
sasl_server_mech_find_def(struct sasl_server *server,
			  const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech_def_reg *mech_dreg;

	mech_dreg = server->mechs_head;
	while (mech_dreg != NULL) {
		if (mech_dreg->def == def)
			break;
		mech_dreg = mech_dreg->next;
	}

	return mech_dreg;
}

static struct sasl_server_mech_def_reg *
sasl_server_mech_find_def_by_name(struct sasl_server *server,
				  const char *mech_name)
{
	struct sasl_server_mech_def_reg *mech_dreg;

	mech_dreg = server->mechs_head;
	while (mech_dreg != NULL) {
		if (strcmp(mech_dreg->def->name, mech_name) == 0)
			break;
		mech_dreg = mech_dreg->next;
	}

	return mech_dreg;
}

static struct sasl_server_mech_def_reg *
sasl_server_mech_register_def(struct sasl_server *server,
			      const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech_def_reg *mech_dreg;

	i_assert(def->funcs != NULL);
	i_assert(strcmp(def->name, t_str_ucase(def->name)) == 0);

	mech_dreg = sasl_server_mech_find_def(server, def);
	if (mech_dreg != NULL) {
		i_assert(mech_dreg->refcount > 0);
		mech_dreg->refcount++;
		return mech_dreg;
	}

	i_assert(sasl_server_mech_find_def_by_name(server, def->name) == NULL);

	mech_dreg = p_new(server->pool, struct sasl_server_mech_def_reg, 1);
	mech_dreg->def = def;
	mech_dreg->refcount = 1;

	DLLIST2_APPEND(&server->mechs_head, &server->mechs_tail, mech_dreg);
	return mech_dreg;
}

static struct sasl_server_mech_reg *
sasl_server_mech_reg_find(struct sasl_server_instance *sinst, const char *name)
{
	struct sasl_server_mech_reg *mech_reg;
	name = t_str_ucase(name);

	for (mech_reg = sinst->mechs_head; mech_reg != NULL;
	     mech_reg = mech_reg->next) {
		if (strcmp(mech_reg->def_reg->def->name, name) == 0)
			return mech_reg;
	}
	return NULL;
}

static struct sasl_server_mech *
sasl_server_mech_create(struct sasl_server_instance *sinst,
			const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech *mech;

	mech = p_new(sinst->pool, struct sasl_server_mech, 1);
	mech->pool = sinst->pool;
	mech->sinst = sinst;
	mech->def = def;

	mech->event = event_create(sinst->event);
	event_drop_parent_log_prefixes(mech->event, 1);
	event_set_append_log_prefix(mech->event,
		t_strdup_printf("sasl(%s): ", t_str_lcase(def->name)));

	return mech;
}

static void sasl_server_mech_free(struct sasl_server_mech *mech)
{
	event_unref(&mech->event);
	mech->def = NULL;
}

static struct sasl_server_mech *
sasl_server_mech_register_common(struct sasl_server_instance *sinst,
				 const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech_def_reg *mech_dreg;
	struct sasl_server_mech_reg *mech_reg;
	struct sasl_server_mech *mech;

	i_assert(sasl_server_mech_reg_find(sinst, def->name) == NULL);

	mech_dreg = sasl_server_mech_register_def(sinst->server, def);

	mech_reg = p_new(sinst->pool, struct sasl_server_mech_reg, 1);
	mech_reg->def_reg = mech_dreg;

	DLLIST_PREPEND_FULL(&mech_dreg->insts, mech_reg, def_prev, def_next);

	mech = sasl_server_mech_create(sinst, def);
	mech->reg = mech_reg;
	mech_reg->mech = mech;

	return mech;
}

struct sasl_server_mech *
sasl_server_mech_register(struct sasl_server_instance *sinst,
			  const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech *mech;

	mech = sasl_server_mech_register_common(sinst, def);
	DLLIST2_APPEND(&sinst->mechs_head, &sinst->mechs_tail, mech->reg);

	return mech;
}

struct sasl_server_mech *
sasl_server_mech_register_hidden(struct sasl_server_instance *sinst,
				 const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech *mech;

	mech = sasl_server_mech_register_common(sinst, def);
	DLLIST_PREPEND(&sinst->mechs_hidden, mech->reg);

	return mech;
}

const struct sasl_server_mech *
sasl_server_mech_find(struct sasl_server_instance *sinst, const char *name)
{
	struct sasl_server_mech_reg *mech_reg;

	mech_reg = sasl_server_mech_reg_find(sinst, name);
	if (mech_reg == NULL)
		return NULL;
	return mech_reg->mech;
}

static void sasl_server_mech_reg_free(struct sasl_server_mech_reg *mech_reg)
{
	struct sasl_server_mech *mech = mech_reg->mech;
	struct sasl_server_mech_def_reg *mech_dreg = mech_reg->def_reg;

	i_assert(mech_dreg->def == mech->def);
	DLLIST_REMOVE_FULL(&mech_dreg->insts, mech_reg, def_prev, def_next);
	mech_reg->mech = NULL;
	sasl_server_mech_free(mech);

	if (mech_dreg->insts == NULL) {
		struct sasl_server *server = mech->sinst->server;

		DLLIST2_REMOVE(&server->mechs_head, &server->mechs_tail,
			       mech_dreg);
		mech_dreg->def = NULL;
	}
}

static struct sasl_server_mech_reg *
sasl_server_mech_reg_list_find(struct sasl_server_mech_reg *mech_reg_list,
			       const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech_reg *mech_reg;

	mech_reg = mech_reg_list;
	while (mech_reg != NULL) {
		struct sasl_server_mech_reg *mech_reg_next = mech_reg->next;

		if (mech_reg->mech->def == def)
			return mech_reg;
		mech_reg = mech_reg_next;
	}
	return NULL;
}

void sasl_server_mech_unregister(struct sasl_server_instance *sinst,
				 const struct sasl_server_mech_def *def)
{
	struct sasl_server_mech_reg *mech_reg;

	mech_reg = sasl_server_mech_reg_list_find(sinst->mechs_head, def);
	if (mech_reg != NULL) {
		DLLIST2_REMOVE(&sinst->mechs_head,
			       &sinst->mechs_tail, mech_reg);
	} else {
		mech_reg = sasl_server_mech_reg_list_find(
			sinst->mechs_hidden, def);
		if (mech_reg != NULL)
			DLLIST_REMOVE(&sinst->mechs_hidden, mech_reg);
	}

	if (mech_reg == NULL)
		return;

	sasl_server_mech_reg_free(mech_reg);
}
