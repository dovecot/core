/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"

bool imap_arg_get_atom(const struct imap_arg *arg, const char **str_r)
{
	if (arg->type != IMAP_ARG_ATOM)
		return FALSE;

	*str_r = arg->_data.str;
	return TRUE;
}

bool imap_arg_get_quoted(const struct imap_arg *arg, const char **str_r)
{
	if (arg->type != IMAP_ARG_STRING)
		return FALSE;

	*str_r = arg->_data.str;
	return TRUE;
}

bool imap_arg_get_string(const struct imap_arg *arg, const char **str_r)
{
	if (arg->type != IMAP_ARG_STRING && arg->type != IMAP_ARG_LITERAL)
		return FALSE;

	*str_r = arg->_data.str;
	return TRUE;
}

bool imap_arg_get_astring(const struct imap_arg *arg, const char **str_r)
{
	if (!IMAP_ARG_IS_ASTRING(arg))
		return FALSE;

	*str_r = arg->_data.str;
	return TRUE;
}

bool imap_arg_get_nstring(const struct imap_arg *arg, const char **str_r)
{
	if (arg->type == IMAP_ARG_NIL) {
		*str_r = NULL;
		return TRUE;
	}
	return imap_arg_get_astring(arg, str_r);
}

bool imap_arg_get_literal_size(const struct imap_arg *arg, uoff_t *size_r)
{
	if (arg->type != IMAP_ARG_LITERAL_SIZE &&
	    arg->type != IMAP_ARG_LITERAL_SIZE_NONSYNC)
		return FALSE;

	*size_r = arg->_data.literal_size;
	return TRUE;
}

bool imap_arg_get_list(const struct imap_arg *arg,
		       const struct imap_arg **list_r)
{
	unsigned int count;

	return imap_arg_get_list_full(arg, list_r, &count);
}

bool imap_arg_get_list_full(const struct imap_arg *arg,
			    const struct imap_arg **list_r,
			    unsigned int *list_count_r)
{
	unsigned int count;

	if (arg->type != IMAP_ARG_LIST)
		return FALSE;

	*list_r = array_get(&arg->_data.list, &count);

	/* drop IMAP_ARG_EOL from list size */
	i_assert(count > 0);
	*list_count_r = count - 1;
	return TRUE;
}

const char *imap_arg_as_astring(const struct imap_arg *arg)
{
	const char *str;

	if (!imap_arg_get_astring(arg, &str))
		i_unreached();
	return str;
}

const char *imap_arg_as_nstring(const struct imap_arg *arg)
{
	const char *str;

	if (!imap_arg_get_nstring(arg, &str))
		i_unreached();
	return str;
}

uoff_t imap_arg_as_literal_size(const struct imap_arg *arg)
{
	uoff_t size;

	if (!imap_arg_get_literal_size(arg, &size))
		i_unreached();
	return size;
}

const struct imap_arg *
imap_arg_as_list(const struct imap_arg *arg)
{
	const struct imap_arg *ret;

	if (!imap_arg_get_list(arg, &ret))
		i_unreached();
	return ret;
}

bool imap_arg_atom_equals(const struct imap_arg *arg, const char *str)
{
	const char *value;

	if (!imap_arg_get_atom(arg, &value))
		return FALSE;
	return strcasecmp(value, str) == 0;
}
