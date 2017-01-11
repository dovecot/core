/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ldap-private.h"

struct ldap_search_iterator* ldap_search_iterator_init(struct ldap_result *result)
{
	struct ldap_search_iterator *iter;

	i_assert(result->openldap_ret == LDAP_SUCCESS);
	i_assert(result->error_string == NULL);

	iter = p_new(result->pool, struct ldap_search_iterator, 1);
	iter->result = result;
	return iter;
}

const struct ldap_entry *ldap_search_iterator_next(struct ldap_search_iterator *iter)
{
	if (iter->idx >= array_count(&(iter->result->entries)))
		return NULL;
	return array_idx(&(iter->result->entries), iter->idx++);
}

void ldap_search_iterator_deinit(struct ldap_search_iterator **iter)
{
	*iter = NULL;
}
