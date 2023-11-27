/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
/* <settings checks> */
#include "strescape.h"
/* </settings checks> */
#include "acl-api-private.h"

/* <settings checks> */
const struct acl_letter_map acl_letter_map[] = {
	{ 'l', MAIL_ACL_LOOKUP },
	{ 'r', MAIL_ACL_READ },
	{ 'w', MAIL_ACL_WRITE },
	{ 's', MAIL_ACL_WRITE_SEEN },
	{ 't', MAIL_ACL_WRITE_DELETED },
	{ 'i', MAIL_ACL_INSERT },
	{ 'p', MAIL_ACL_POST },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

const char *const all_mailbox_rights[] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_POST,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN,
	NULL
};

static_assert(N_ELEMENTS(acl_letter_map) == N_ELEMENTS(all_mailbox_rights),
	     "acl_letter_map size differs from all_mailbox_rights");

/* </settings checks> */

void acl_rights_write_id(string_t *dest, const struct acl_rights *right)
{
	switch (right->id_type) {
	case ACL_ID_ANYONE:
		str_append(dest, ACL_ID_NAME_ANYONE);
		break;
	case ACL_ID_AUTHENTICATED:
		str_append(dest, ACL_ID_NAME_AUTHENTICATED);
		break;
	case ACL_ID_OWNER:
		str_append(dest, ACL_ID_NAME_OWNER);
		break;
	case ACL_ID_USER:
		str_append(dest, ACL_ID_NAME_USER_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_GROUP:
		str_append(dest, ACL_ID_NAME_GROUP_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_GROUP_OVERRIDE:
		str_append(dest, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX);
		str_append(dest, right->identifier);
		break;
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}
}

const char *acl_rights_get_id(const struct acl_rights *right)
{
	string_t *str = t_str_new(32);

	acl_rights_write_id(str, right);
	return str_c(str);
}

static bool is_standard_right(const char *name)
{
	unsigned int i;

	for (i = 0; all_mailbox_rights[i] != NULL; i++) {
		if (strcmp(all_mailbox_rights[i], name) == 0)
			return TRUE;
	}
	return FALSE;
}

int acl_rights_update_import(struct acl_rights_update *update,
			     const char *id, const char *const *rights,
			     const char **error_r)
{
	ARRAY_TYPE(const_string) dest_rights, dest_neg_rights, *dest;
	unsigned int i, j;

	if (acl_identifier_parse(id, &update->rights) < 0) {
		*error_r = t_strdup_printf("Invalid ID: %s", id);
		return -1;
	}
	if (rights == NULL) {
		update->modify_mode = ACL_MODIFY_MODE_CLEAR;
		update->neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
		return 0;
	}

	t_array_init(&dest_rights, 8);
	t_array_init(&dest_neg_rights, 8);
	for (i = 0; rights[i] != NULL; i++) {
		const char *right = rights[i];

		if (right[0] != '-')
			dest = &dest_rights;
		else {
			right++;
			dest = &dest_neg_rights;
		}
		if (strcmp(right, "all") != 0) {
			if (*right == ':') {
				/* non-standard right */
				right++;
				array_push_back(dest, &right);
			} else if (is_standard_right(right)) {
				array_push_back(dest, &right);
			} else {
				*error_r = t_strdup_printf("Invalid right '%s'",
							   right);
				return -1;
			}
		} else {
			for (j = 0; all_mailbox_rights[j] != NULL; j++)
				array_push_back(dest, &all_mailbox_rights[j]);
		}
	}
	if (array_count(&dest_rights) > 0) {
		array_append_zero(&dest_rights);
		update->rights.rights = array_front(&dest_rights);
	} else if (update->modify_mode == ACL_MODIFY_MODE_REPLACE) {
		update->modify_mode = ACL_MODIFY_MODE_CLEAR;
	}
	if (array_count(&dest_neg_rights) > 0) {
		array_append_zero(&dest_neg_rights);
		update->rights.neg_rights = array_front(&dest_neg_rights);
	} else if (update->neg_modify_mode == ACL_MODIFY_MODE_REPLACE) {
		update->neg_modify_mode = ACL_MODIFY_MODE_CLEAR;
	}
	return 0;
}

const char *acl_rights_export(const struct acl_rights *rights)
{
	string_t *str = t_str_new(128);

	if (rights->rights != NULL)
		str_append(str, t_strarray_join(rights->rights, " "));
	if (rights->neg_rights != NULL && rights->neg_rights[0] != NULL) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append_c(str, '-');
		str_append(str, t_strarray_join(rights->neg_rights, " -"));
	}
	return str_c(str);
}

/* <settings checks> */
int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r)
{
	const char *id_str, *const *right_names, *error = NULL;

	/* <id> [<imap acls>] [:<named acls>] */
	if (*line == '"') {
		line++;
		if (str_unescape_next(&line, &id_str) < 0 ||
		    (line[0] != ' ' && line[0] != '\0')) {
			*error_r = "Invalid quoted ID";
			return -1;
		}
		if (line[0] == ' ')
			line++;
	} else {
		id_str = line;
		line = strchr(id_str, ' ');
		if (line == NULL)
			line = "";
		else
			id_str = t_strdup_until(id_str, line++);
	}

	i_zero(rights_r);

	right_names = acl_right_names_parse(pool, line, &error);
	if (*id_str != '-')
		rights_r->rights = right_names;
	else {
		id_str++;
		rights_r->neg_rights = right_names;
	}

	if (acl_identifier_parse(id_str, rights_r) < 0)
		error = t_strdup_printf("Unknown ID '%s'", id_str);

	if (error != NULL) {
		*error_r = error;
		return -1;
	}

	rights_r->identifier = p_strdup(pool, rights_r->identifier);
	return 0;
}
/* </settings checks> */

void acl_rights_dup(const struct acl_rights *src,
		    pool_t pool, struct acl_rights *dest_r)
{
	i_zero(dest_r);
	dest_r->id_type = src->id_type;
	dest_r->identifier = p_strdup(pool, src->identifier);
	dest_r->rights = src->rights == NULL ? NULL :
		p_strarray_dup(pool, src->rights);
	dest_r->neg_rights = src->neg_rights == NULL ? NULL :
		p_strarray_dup(pool, src->neg_rights);
	dest_r->global = src->global;
}

int acl_rights_cmp(const struct acl_rights *r1, const struct acl_rights *r2)
{
	int ret;

	if (r1->global != r2->global) {
		/* globals have higher priority than locals */
		return r1->global ? 1 : -1;
	}

	ret = (int)r1->id_type - (int)r2->id_type;
	if (ret != 0)
		return ret;

	return null_strcmp(r1->identifier, r2->identifier);
}

bool acl_rights_has_nonowner_lookup_changes(const struct acl_rights *rights)
{
	const char *const *p;

	if (rights->id_type == ACL_ID_OWNER) {
		/* ignore owner rights */
		return FALSE;
	}

	if (rights->rights == NULL)
		return FALSE;

	for (p = rights->rights; *p != NULL; p++) {
		if (strcmp(*p, MAIL_ACL_LOOKUP) == 0)
			return TRUE;
	}
	return FALSE;
}

/* <settings checks> */
int acl_identifier_parse(const char *line, struct acl_rights *rights)
{
	if (str_begins(line, ACL_ID_NAME_USER_PREFIX, &rights->identifier)) {
		rights->id_type = ACL_ID_USER;
	} else if (strcmp(line, ACL_ID_NAME_OWNER) == 0) {
		rights->id_type = ACL_ID_OWNER;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_PREFIX,
			      &rights->identifier)) {
		rights->id_type = ACL_ID_GROUP;
	} else if (str_begins(line, ACL_ID_NAME_GROUP_OVERRIDE_PREFIX,
			      &rights->identifier)) {
		rights->id_type = ACL_ID_GROUP_OVERRIDE;
	} else if (strcmp(line, ACL_ID_NAME_AUTHENTICATED) == 0) {
		rights->id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(line, ACL_ID_NAME_ANYONE) == 0 ||
		   strcmp(line, "anonymous") == 0) {
		rights->id_type = ACL_ID_ANYONE;
	} else {
		return -1;
	}
	return 0;
}

static const char *const *
acl_right_names_alloc(pool_t pool, ARRAY_TYPE(const_string) *rights_arr,
		      bool dup_strings)
{
	const char **ret, *const *rights;
	unsigned int i, dest, count;

	/* sort the rights first so we can easily drop duplicates */
	array_sort(rights_arr, i_strcmp_p);

	/* @UNSAFE */
	rights = array_get(rights_arr, &count);
	ret = p_new(pool, const char *, count + 1);
	if (count > 0) {
		ret[0] = rights[0];
		for (i = dest = 1; i < count; i++) {
			if (strcmp(rights[i-1], rights[i]) != 0)
				ret[dest++] = rights[i];
		}
		ret[dest] = NULL;
		if (dup_strings) {
			for (i = 0; i < dest; i++)
				ret[i] = p_strdup(pool, ret[i]);
		}
	}
	return ret;
}

const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r)
{
	ARRAY_TYPE(const_string) rights;
	const char *const *names;
	unsigned int i;

	/* parse IMAP ACL list */
	while (*acl == ' ' || *acl == '\t')
		acl++;

	t_array_init(&rights, 64);
	while (*acl != '\0' && *acl != ' ' && *acl != '\t' && *acl != ':') {
		for (i = 0; acl_letter_map[i].letter != '\0'; i++) {
			if (acl_letter_map[i].letter == *acl)
				break;
		}

		if (acl_letter_map[i].letter == '\0') {
			*error_r = t_strdup_printf("Unknown ACL '%c'", *acl);
			return NULL;
		}

		array_push_back(&rights, &acl_letter_map[i].name);
		acl++;
	}
	while (*acl == ' ' || *acl == '\t') acl++;

	if (*acl != '\0') {
		/* parse our own extended ACLs */
		if (*acl != ':') {
			*error_r = "Missing ':' prefix in ACL extensions";
			return NULL;
		}

		names = t_strsplit_spaces(acl + 1, ", \t");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_push_back(&rights, &name);
		}
	}

	return acl_right_names_alloc(pool, &rights, FALSE);
}
/* </settings checks> */

void acl_right_names_write(string_t *dest, const char *const *rights)
{
	char c2[2];
	unsigned int i, j, pos;

	c2[1] = '\0';
	pos = str_len(dest);
	for (i = 0; rights[i] != NULL; i++) {
		/* use letters if possible */
		for (j = 0; acl_letter_map[j].name != NULL; j++) {
			if (strcmp(rights[i], acl_letter_map[j].name) == 0) {
				c2[0] = acl_letter_map[j].letter;
				str_insert(dest, pos, c2);
				pos++;
				break;
			}
		}
		if (acl_letter_map[j].name == NULL) {
			/* fallback to full name */
			str_append_c(dest, ' ');
			str_append(dest, rights[i]);
		}
	}
	if (pos + 1 < str_len(dest)) {
		c2[0] = ':';
		str_insert(dest, pos + 1, c2);
	}
}

void acl_right_names_merge(pool_t pool, const char *const **destp,
			   const char *const *src, bool dup_strings)
{
	const char *const *dest = *destp;
	ARRAY_TYPE(const_string) rights;
	unsigned int i;

	t_array_init(&rights, 64);
	if (dest != NULL) {
		for (i = 0; dest[i] != NULL; i++)
			array_push_back(&rights, &dest[i]);
	}
	if (src != NULL) {
		for (i = 0; src[i] != NULL; i++)
			array_push_back(&rights, &src[i]);
	}

	*destp = acl_right_names_alloc(pool, &rights, dup_strings);
}

bool acl_right_names_modify(pool_t pool,
			    const char *const **rightsp,
			    const char *const *modify_rights,
			    enum acl_modify_mode modify_mode)
{
	const char *const *old_rights = *rightsp;
	const char *const *new_rights = NULL;
	ARRAY_TYPE(const_string) rights;
	unsigned int i, j;

	if (modify_rights == NULL && modify_mode != ACL_MODIFY_MODE_CLEAR) {
		/* nothing to do here */
		return FALSE;
	}

	switch (modify_mode) {
	case ACL_MODIFY_MODE_REMOVE:
		if (old_rights == NULL || *old_rights == NULL) {
			/* nothing to do */
			return FALSE;
		}
		t_array_init(&rights, 64);
		for (i = 0; old_rights[i] != NULL; i++) {
			for (j = 0; modify_rights[j] != NULL; j++) {
				if (strcmp(old_rights[i], modify_rights[j]) == 0)
					break;
			}
			if (modify_rights[j] == NULL)
				array_push_back(&rights, &old_rights[i]);
		}
		new_rights = empty_str_array;
		modify_rights = array_count(&rights) == 0 ? NULL :
			array_front(&rights);
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_ADD:
		new_rights = old_rights;
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_REPLACE:
		new_rights = empty_str_array;
		acl_right_names_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_CLEAR:
		if (*rightsp == NULL) {
			/* ACL didn't exist before either */
			return FALSE;
		}
		*rightsp = NULL;
		return TRUE;
	}
	i_assert(new_rights != NULL);
	*rightsp = new_rights;

	if (old_rights == NULL)
		return new_rights[0] != NULL;

	/* see if anything changed */
	for (i = 0; old_rights[i] != NULL && new_rights[i] != NULL; i++) {
		if (strcmp(old_rights[i], new_rights[i]) != 0)
			return TRUE;
	}
	return old_rights[i] != NULL || new_rights[i] != NULL;
}

