#ifndef __TEMP_MEMPOOL_H
#define __TEMP_MEMPOOL_H

/* temporary memory allocations. All t_..() allocations between
   t_push() and t_pop() are free'd after t_pop() is called. */
int t_push(void);
int t_pop(void);

/* WARNING: Be careful when using this functions, it's too easy to
   accidentally save the returned value somewhere permanently.

   You probably should never use this function directly, rather
   create functions that return 'const xxx*' types and use t_malloc()
   internally in them. This is a lot safer, since usually compiler
   warns if you try to place them in xxx*. See strfuncs.c for examples. */
void *t_malloc(unsigned int size);
void *t_malloc0(unsigned int size);

/* Try growing allocated memory. Returns TRUE if successful. */
int t_try_grow(void *mem, unsigned int size);

#define t_new(type, count) \
	((type *) t_malloc0((unsigned) sizeof(type) * (count)))

/* Returns pointer to temporary buffer you can use. The buffer will be
   invalid as soon as t_malloc() or t_pop() is called!

   If you wish to grow the buffer, you must give the full wanted size
   in the size parameter. If return value doesn't point to the same value
   as last time, you need to memcpy() the data from old buffer the this
   new one (or do some other trickery). See t_buffer_reget(). */
#define t_buffer_get_type(type, size) \
	t_buffer_get(sizeof(type) * (size))
void *t_buffer_get(unsigned int size);

/* Grow the buffer, memcpy()ing the memory to new location if needed. */
#define t_buffer_reget_type(buffer, type, size) \
	t_buffer_reget(buffer, sizeof(type) * (size))
void *t_buffer_reget(void *buffer, unsigned int size);

/* Make given t_buffer_get()ed buffer permanent. Note that size MUST be
   less or equal than the size you gave with last t_buffer_get() or the
   result will be undefined. */
#define t_buffer_alloc_type(type, size) \
        t_buffer_alloc(sizeof(type) * (size))
void t_buffer_alloc(unsigned int size);

void temp_mempool_init(void);
void temp_mempool_deinit(void);

#endif
