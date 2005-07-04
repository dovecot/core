#ifndef __ARRAY_DECL_H
#define __ARRAY_DECL_H

#if defined (DEBUG) && defined (__GNUC__)
#  define ARRAY_TYPE_CHECKS
#endif

#ifdef ARRAY_TYPE_CHECKS
#  define ARRAY_DEFINE(name, array_type) name; array_type *name ## __ ## type
#  define ARRAY_DEFINE_EXTERN(name, array_type) \
	name; extern array_type *name ## __ ## type
#  define ARRAY_DEFINE_PTR(name, array_type) \
	name; array_type **name ## __ ## type
#  define ARRAY_INIT { 0, 0 }, 0
#else
#  define ARRAY_DEFINE(name, array_type) name
#  define ARRAY_DEFINE_EXTERN(name, array_type) name
#  define ARRAY_DEFINE_PTR(name, array_type) name
#  define ARRAY_INIT { 0, 0 }
#endif

struct array {
	buffer_t *buffer;
	size_t element_size;
};

#endif
