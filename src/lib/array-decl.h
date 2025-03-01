#ifndef ARRAY_DECL_H
#define ARRAY_DECL_H

#define ARRAY(array_type) union { struct array arr; array_type const *const *v; array_type **v_modifiable; }
#define ARRAY_INIT { { NULL, 0 } }

#define ARRAY_DEFINE_TYPE(name, array_type) \
	union array ## __ ## name { struct array arr; array_type const *const *v; array_type **v_modifiable; }
#define ARRAY_TYPE(name) \
	union array ## __ ## name

struct array {
	buffer_t *buffer;
	size_t element_size;
};

ARRAY_DEFINE_TYPE(string, char *);
ARRAY_DEFINE_TYPE(const_string, const char *);
ARRAY_DEFINE_TYPE(bool, bool);
ARRAY_DEFINE_TYPE(uint8_t, uint8_t);
ARRAY_DEFINE_TYPE(uint16_t, uint16_t);
ARRAY_DEFINE_TYPE(uint32_t, uint32_t);
ARRAY_DEFINE_TYPE(uint64_t, uint64_t);
ARRAY_DEFINE_TYPE(uint, unsigned int);
ARRAY_DEFINE_TYPE(void_array, void *);

#endif
