/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ldap-private.h"

int ldap_entry_init(struct ldap_entry *obj, struct ldap_result *result,
	LDAPMessage *message)
{
	ARRAY_TYPE(const_string) attr_names;
	struct berval **values;
	int count;
	BerElement *bptr;
	char *tmp;
	tmp = ldap_get_dn(result->conn->conn, message);
	obj->dn = p_strdup(result->pool, tmp);
	obj->result = result;
	ldap_memfree(tmp);

	tmp = ldap_first_attribute(result->conn->conn, message, &bptr);

	p_array_init(&attr_names, result->pool, 8);
	p_array_init(&obj->attributes, result->pool, 8);

	while(tmp != NULL) {
		struct ldap_attribute *attr = p_new(result->pool, struct ldap_attribute, 1);
		attr->name = p_strdup(result->pool, tmp);
		array_append(&attr_names, &attr->name, 1);
		values = ldap_get_values_len(result->conn->conn, message, tmp);
		if (values != NULL) {
			count = ldap_count_values_len(values);
			p_array_init(&attr->values, result->pool, count);
			for(int i = 0; i < count; i++) {
				const char *ptr = p_strndup(result->pool, values[i]->bv_val, values[i]->bv_len);
				array_append(&attr->values, &ptr, 1);
			}
			ldap_value_free_len(values);
		}
		array_append_zero(&attr->values);
		ldap_memfree(tmp);
		array_append(&obj->attributes, attr, 1);
		tmp = ldap_next_attribute(result->conn->conn, message, bptr);
	}

	ber_free(bptr, 0);

	array_append_zero(&attr_names);
	obj->attr_names = array_first(&attr_names);

	return 0;
}

const char *ldap_entry_dn(const struct ldap_entry *entry)
{
	return entry->dn;
}

const char *const *ldap_entry_get_attributes(const struct ldap_entry *entry)
{
	return entry->attr_names;
}

const char *const *ldap_entry_get_attribute(const struct ldap_entry *entry, const char *attribute)
{
	const struct ldap_attribute *attr;
	array_foreach(&entry->attributes, attr) {
		if (strcasecmp(attr->name, attribute) == 0) {
			return array_first(&attr->values);
		}
	}
	return NULL;
}
