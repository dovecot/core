#ifndef __ARRAY_H
#define __ARRAY_H

#include "buffer.h"

/* Array is a buffer accessible using fixed size elements. If DEBUG is
   enabled, it also provides compile time type safety:

   If DEBUG is enabled, an extra variable is defined along with the array
   itself. This is used to cast array_idx() return value correctly, so
   compiler gives a warning if it's assigned into variable with a different
   type.

   Example usage:

   struct foo {
	array_t ARRAY_DEFINE(bars, struct bar);
	...
   };

   ARRAY_CREATE(&foo->bars, default_pool, struct bar, 10);
   ARRAY_CREATE(&foo->bars, default_pool, struct baz, 10); // compiler warning

   struct bar *bar = array_idx(&foo->bars, 5);
   struct baz *baz = array_idx(&foo->bars, 5); // compiler warning

   When passing array_t as a parameter to function, or when it's otherwise
   accessed in a way that the extra variable cannot be accessed, the code
   won't compile. For situations like those, there's a ARRAY_SET_TYPE() macro.

   Example:

   void do_foo(array_t *bars) {
	ARRAY_SET_TYPE(bars, struct foo);
	struct foo *foo = array_idx(bars, 0);
   }
*/
#if defined (DEBUG) && defined (__GNUC__)
#  define ARRAY_TYPE_CHECKS
#endif

#ifdef ARRAY_TYPE_CHECKS
#  define ARRAY_DEFINE(name, array_type) name; array_type *name ## __ ## type
#  define ARRAY_CREATE(array, pool, array_type, init_count) STMT_START { \
	array_type *_array_tmp = *(array ## __ ## type); _array_tmp = NULL; \
	array_create(array, pool, sizeof(array_type), init_count); \
	} STMT_END
#  define ARRAY_SET_TYPE(array, array_type) \
	array_type **array ## __ ## type = NULL
#  define ARRAY_INIT { 0, 0 }, 0
#else
#  define ARRAY_DEFINE(name, array_type) name
#  define ARRAY_CREATE(array, pool, array_type, init_count) \
	array_create(array, pool, sizeof(array_type), init_count);
#  define ARRAY_SET_TYPE(array, array_type)
#  define ARRAY_INIT { 0, 0 }
#endif

struct array {
	buffer_t *buffer;
	size_t element_size;
};

static inline void
array_create_from_buffer(array_t *array, buffer_t *buffer, size_t element_size)
{
	array->buffer = buffer;
	array->element_size = element_size;
}

static inline void
array_create(array_t *array, pool_t pool,
	     size_t element_size, unsigned int init_count)
{
	buffer_t *buffer;

        buffer = buffer_create_dynamic(pool, init_count * element_size);
	array_create_from_buffer(array, buffer, element_size);
}

static inline void
array_free(array_t *array)
{
	buffer_free(array->buffer);
	array->buffer = NULL;
}

static inline int
array_is_created(const array_t *array)
{
	return array->buffer != NULL;
}

static inline void
array_clear(array_t *array)
{
	buffer_set_used_size(array->buffer, 0);
}

static inline void
_array_append(array_t *array, const void *data, unsigned int count)
{
	buffer_append(array->buffer, data, count * array->element_size);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_append _array_append
#else
#  define array_append(array, data, count) STMT_START { \
	typeof(*(array ## __ ## type)) _array_tmp = data; \
	_array_append(array, _array_tmp, count); \
	} STMT_END
#endif

static inline void
array_append_array(array_t *dest_array, const array_t *src_array)
{
	i_assert(dest_array->element_size == src_array->element_size);
	buffer_append_buf(dest_array->buffer, src_array->buffer, 0, (size_t)-1);
}

static inline void
_array_insert(array_t *array, unsigned int idx,
	      const void *data, unsigned int count)
{
	buffer_insert(array->buffer, idx * array->element_size,
		      data, count * array->element_size);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_insert _array_insert
#else
#  define array_insert(array, idx, data, count) STMT_START { \
	typeof(*(array ## __ ## type)) _array_tmp = data; \
	_array_insert(array, idx, _array_tmp, count); \
	} STMT_END
#endif

static inline void
array_delete(array_t *array, unsigned int idx, unsigned int count)
{
	buffer_delete(array->buffer, idx * array->element_size,
		      count * array->element_size);
}

static inline const void *
_array_get(const array_t *array, unsigned int *count_r)
{
	if (count_r != NULL)
		*count_r = array->buffer->used / array->element_size;
	return array->buffer->data;
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_get _array_get
#else
#  define array_get(array, count) \
	(const typeof(*(array ## __ ## type)))_array_get(array, count)
#endif

static inline const void *
_array_idx(const array_t *array, unsigned int idx)
{
	i_assert(idx * array->element_size < array->buffer->used);
	return CONST_PTR_OFFSET(array->buffer->data, idx * array->element_size);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_idx _array_idx
#else
#  define array_idx(array, idx) \
	(const typeof(*(array ## __ ## type)))_array_idx(array, idx)
#endif

static inline void *
_array_get_modifyable(array_t *array, unsigned int *count_r)
{
	if (count_r != NULL)
		*count_r = array->buffer->used / array->element_size;
	return buffer_get_modifyable_data(array->buffer, NULL);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_get_modifyable _array_get_modifyable
#else
#  define array_get_modifyable(array, count) \
	(typeof(*(array ## __ ## type))) \
		_array_get_modifyable(array, count)
#endif

static inline void *
_array_modifyable_idx(array_t *array, unsigned int idx)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos >= array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos + array->element_size -
				   array->buffer->used);
	}
	return buffer_get_space_unsafe(array->buffer, pos, array->element_size);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_modifyable_idx _array_modifyable_idx
#else
#  define array_modifyable_idx(array, count) \
	(typeof(*(array ## __ ## type))) \
		_array_modifyable_idx(array, count)
#endif

static inline void
_array_idx_set(array_t *array, unsigned int idx, const void *data)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos > array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos - array->buffer->used);
	}
	buffer_write(array->buffer, pos, data, array->element_size);
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_idx_set _array_idx_set
#else
#  define array_idx_set(array, idx, data) STMT_START { \
	typeof(*(array ## __ ## type)) _array_tmp = data; \
	_array_idx_set(array, idx, _array_tmp); \
	} STMT_END
#endif

static inline void *
_array_modifyable_append(array_t *array)
{
	void *data;

	data = buffer_append_space_unsafe(array->buffer, array->element_size);
	memset(data, 0, array->element_size);
	return data;
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_modifyable_append _array_modifyable_append
#else
#  define array_modifyable_append(array) \
	(typeof(*(array ## __ ## type))) \
		_array_modifyable_append(array)
#endif

static inline void *
_array_modifyable_insert(array_t *array, unsigned int idx)
{
	void *data;
	size_t pos;

	pos = idx * array->element_size;
	buffer_copy(array->buffer, pos + array->element_size,
		    array->buffer, pos, (size_t)-1);

	data = buffer_get_space_unsafe(array->buffer, pos, array->element_size);
	memset(data, 0, array->element_size);
	return data;
}
#ifndef ARRAY_TYPE_CHECKS
#  define array_modifyable_insert _array_modifyable_insert
#else
#  define array_modifyable_insert(array, idx) \
	(typeof(*(array ## __ ## type))) \
		_array_modifyable_insert(array, idx)
#endif

static inline unsigned int
array_count(const array_t *array)
{
	return array->buffer->used / array->element_size;
}

#endif
