#ifndef MAIL_STORAGE_LUA_PRIVATE_H
#define MAIL_STORAGE_LUA_PRIVATE_H 1

#define DLUA_MAILBOX_EQUALS(a, b) \
	mailbox_equals((a), mailbox_get_namespace(b), mailbox_get_vname(b))

struct lua_storage_keyvalue {
	const char *key;
	const char *value;
	size_t value_len;
};

ARRAY_DEFINE_TYPE(lua_storage_keyvalue, struct lua_storage_keyvalue);

void lua_storage_mail_register(struct dlua_script *script);
void lua_storage_mail_user_register(struct dlua_script *script);
void lua_storage_mailbox_register(struct dlua_script *script);

int lua_storage_cmp(lua_State *L);

int lua_storage_mailbox_attribute_get(struct mailbox *box, const char *key,
				      const char **value_r, size_t *value_len_r,
				      const char **error_r);
int lua_storage_mailbox_attribute_set(struct mailbox *box, const char *key,
				      const char *value, size_t value_len,
				      const char **error_r);
int lua_storage_mailbox_attribute_list(struct mailbox *box, const char *prefix,
				       ARRAY_TYPE(lua_storage_keyvalue) *items_r,
				       const char **error_r);

#endif
