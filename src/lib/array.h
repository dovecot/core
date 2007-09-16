#ifndef ARRAY_H
#define ARRAY_H

/* Array is a buffer accessible using fixed size elements. As long as the
   compiler provides typeof() function, the array provides type safety. If
   a wrong type is tried to be added to the array, or if the array's contents
   are tried to be used using a wrong type, the compiler will give a warning.

   Example usage:

   struct foo {
	ARRAY_DEFINE(bars, struct bar);
	...
   };

   i_array_init(&foo->bars, 10);

   struct bar *bar = array_idx(&foo->bars, 5);
   struct baz *baz = array_idx(&foo->bars, 5); // compiler warning

   If you want to pass an array as a parameter to a function, you'll need to
   create a type for the array using ARRAY_DEFINE_TYPE() and use the type in
   the parameter using ARRAY_TYPE().

   Example:

   ARRAY_DEFINE_TYPE(foo, struct foo);
   void do_foo(ARRAY_TYPE(foo) *bars) {
	struct foo *foo = array_idx(bars, 0);
   }
*/
#include "array-decl.h"
#include "buffer.h"

#define p_array_init(array, pool, init_count) \
	array_create(array, pool, sizeof(**(array)->v), init_count)
#define i_array_init(array, init_count) \
	p_array_init(array, default_pool, init_count)
#define t_array_init(array, init_count) \
	p_array_init(array, pool_datastack_create(), init_count)

#ifdef __GNUC__
#  define ARRAY_TYPE_CAST_CONST(array) \
	(typeof(*(array)->v))
#  define ARRAY_TYPE_CAST_MODIFIABLE(array) \
	(typeof(*(array)->v_modifiable))
#  define ARRAY_TYPE_CHECK(array, data) \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		**(array)->v_modifiable, *data)
#else
#  define ARRAY_TYPE_CAST_CONST(array)
#  define ARRAY_TYPE_CAST_MODIFIABLE(array)
#  define ARRAY_TYPE_CHECK(array, data) 0
#endif

static inline void
_array_create_from_buffer(struct array *array, buffer_t *buffer,
			  size_t element_size)
{
	array->buffer = buffer;
	array->element_size = element_size;
}
#define array_create_from_buffer(array, buffer, element_size) \
	_array_create_from_buffer(&(array)->arr, buffer, element_size)

static inline void
_array_create(struct array *array, pool_t pool,
	      size_t element_size, unsigned int init_count)
{
	buffer_t *buffer;

        buffer = buffer_create_dynamic(pool, init_count * element_size);
	_array_create_from_buffer(array, buffer, element_size);
}
#define array_create(array, pool, element_size, init_count) \
	_array_create(&(array)->arr, pool, element_size, init_count)

static inline void
_array_free(struct array *array)
{
	buffer_free(&array->buffer);
}
#define array_free(array) \
	_array_free(&(array)->arr)

static inline bool
_array_is_created(const struct array *array)
{
	return array->buffer != NULL;
}
#define array_is_created(array) \
	_array_is_created(&(array)->arr)

static inline void
_array_clear(struct array *array)
{
	buffer_set_used_size(array->buffer, 0);
}
#define array_clear(array) \
	_array_clear(&(array)->arr)

static inline void
_array_append(struct array *array, const void *data, unsigned int count)
{
	buffer_append(array->buffer, data, count * array->element_size);
}

#define array_append(array, data, count) \
	_array_append(&(array)->arr + ARRAY_TYPE_CHECK(array, data), \
		data, count)

static inline void
_array_append_array(struct array *dest_array, const struct array *src_array)
{
	i_assert(dest_array->element_size == src_array->element_size);
	buffer_append_buf(dest_array->buffer, src_array->buffer, 0, (size_t)-1);
}
#define array_append_array(dest_array, src_array) \
	_array_append_array(&(dest_array)->arr, &(src_array)->arr)

static inline void
_array_insert(struct array *array, unsigned int idx,
	      const void *data, unsigned int count)
{
	buffer_insert(array->buffer, idx * array->element_size,
		      data, count * array->element_size);
}

#define array_insert(array, idx, data, count) \
	_array_insert(&(array)->arr + ARRAY_TYPE_CHECK(array, data), \
		idx, data, count)

static inline void
_array_delete(struct array *array, unsigned int idx, unsigned int count)
{
	buffer_delete(array->buffer, idx * array->element_size,
		      count * array->element_size);
}
#define array_delete(array, idx, count) \
	_array_delete(&(array)->arr, idx, count)

static inline const void *
_array_get(const struct array *array, unsigned int *count_r)
{
	*count_r = array->buffer->used / array->element_size;
	return array->buffer->data;
}
#define array_get(array, count) \
	ARRAY_TYPE_CAST_CONST(array)_array_get(&(array)->arr, count)

static inline const void *
_array_idx(const struct array *array, unsigned int idx)
{
	i_assert(idx * array->element_size < array->buffer->used);
	return CONST_PTR_OFFSET(array->buffer->data, idx * array->element_size);
}
#define array_idx(array, idx) \
	ARRAY_TYPE_CAST_CONST(array)_array_idx(&(array)->arr, idx)

static inline void *
_array_get_modifiable(struct array *array, unsigned int *count_r)
{
	*count_r = array->buffer->used / array->element_size;
	return buffer_get_modifiable_data(array->buffer, NULL);
}
#define array_get_modifiable(array, count) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		_array_get_modifiable(&(array)->arr, count)

static inline void *
_array_idx_modifiable(struct array *array, unsigned int idx)
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
#define array_idx_modifiable(array, idx) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		_array_idx_modifiable(&(array)->arr, idx)

static inline void
_array_idx_set(struct array *array, unsigned int idx, const void *data)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos > array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos - array->buffer->used);
	}
	buffer_write(array->buffer, pos, data, array->element_size);
}
#define array_idx_set(array, idx, data) \
	_array_idx_set(&(array)->arr + ARRAY_TYPE_CHECK(array, data), idx, data)

static inline void
_array_idx_clear(struct array *array, unsigned int idx)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos > array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos - array->buffer->used);
	} else {
		buffer_write_zero(array->buffer, pos, array->element_size);
	}
}
#define array_idx_clear(array, idx) \
	_array_idx_clear(&(array)->arr, idx)

static inline void *
_array_append_space(struct array *array)
{
	void *data;

	data = buffer_append_space_unsafe(array->buffer, array->element_size);
	memset(data, 0, array->element_size);
	return data;
}
#define array_append_space(array) \
	ARRAY_TYPE_CAST_MODIFIABLE(array)_array_append_space(&(array)->arr)

static inline void *
_array_insert_space(struct array *array, unsigned int idx)
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
#define array_insert_space(array, idx) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		_array_insert_space(&(array)->arr, idx)

static inline unsigned int
_array_count(const struct array *array)
{
	return array->buffer->used / array->element_size;
}
#define array_count(array) \
	_array_count(&(array)->arr)

static inline bool
_array_cmp(const struct array *array1, const struct array *array2)
{
	if (!_array_is_created(array1) || array1->buffer->used == 0)
		return !_array_is_created(array2) || array2->buffer->used == 0;

	if (!_array_is_created(array2))
		return FALSE;

	return buffer_cmp(array1->buffer, array2->buffer);
}
#define array_cmp(array1, array2) \
	_array_cmp(&(array1)->arr, &(array2)->arr)

#endif
