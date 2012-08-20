#ifndef HASH_DECL_H
#define HASH_DECL_H

#define HASH_TABLE_UNION(key_type, value_type) { \
		struct hash_table *_table; \
		key_type _key; \
		value_type _value; \
	}

#define HASH_TABLE_DEFINE_TYPE(name, key_type, value_type) \
	union hash ## __ ## name HASH_TABLE_UNION(key_type, value_type)
#define HASH_TABLE(key_type, value_type) \
	union HASH_TABLE_UNION(key_type, value_type)
#define HASH_TABLE_TYPE(name) \
	union hash ## __ ## name

#endif
