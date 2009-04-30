#ifndef ARRAY_DECL_H
#define ARRAY_DECL_H

#define ARRAY_DEFINE(name, array_type) union { struct array arr; array_type const *const *v; array_type **v_modifiable; } name
#define ARRAY_INIT { { 0, 0 } }

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
ARRAY_DEFINE_TYPE(uint32_t, uint32_t);
ARRAY_DEFINE_TYPE(uint, unsigned int);
ARRAY_DEFINE_TYPE(void_array, void *);

#endif
