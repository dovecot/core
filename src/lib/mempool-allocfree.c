/*
 mempool-allocfree.c : Memory pool manager for custom alloc+free

    Copyright (c) 2001-2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


/* TODO:

    - p_free() could check better that it's freeing a properly allocated
      memory from pool it was told to.

    - try to keep optimal pool sizes ie. keep them in the size they're
      using 90% of the time
    - add statistics functions that print/return the memory usage
    - don't free() anything, save them to unused-list and reuse later.
*/

/* extensive debugging */
/* #define POOL_DEBUG */

/* always clear the memory area that has been free'd. for debugging mostly */
/* #define POOL_FREE_CLEAR 0xd0 */

/* Save the used pool block for each memory allocation, so you can be sure
   that the memory is being free'd from correct pool. Also, with this option
   we don't need to compare pointers which makes this code fully ANSI-C
   compatible :) */
#define POOL_SAVE_BLOCK

#include "lib.h"
#include "mempool.h"

#include <stdlib.h>

#define is_pool(pool) ((pool) != NULL && (pool)->magic == 0xbeef)

#define check_pool(pool) \
	if (!is_pool(pool)) \
		i_panic("Trying to use invalid memory pool, aborting")

#define MEM_FREE_BIT 0x80000000

#define is_mem_free(size) (((size) & MEM_FREE_BIT) != 0)
#define mem_size(size) ((size) & ~MEM_FREE_BIT)

#define mem2int(_mem, _int) \
	memcpy(&(_int), ((unsigned char *) (_mem)), sizeof(int));

#define int2mem(_mem, _int) \
	memcpy(((unsigned char *) (_mem)), &(_int), sizeof(int));

#ifdef POOL_SAVE_BLOCK
#  define ALLOC_EXTRA_SIZE sizeof(PoolBlock *)
#else
#  define ALLOC_EXTRA_SIZE 0
#endif

/* max. number of bytes to even try to allocate. This is done just to avoid
   allocating less memory than was actually requested because of integer
   overflows. -128 is much more than is actually needed. */
#define MAX_ALLOC_SIZE (UINT_MAX - 128)

typedef struct {
        /* total number of bytes in data[] */
	unsigned int size;
        /* free data position at data+free_index, none if >= size */
	unsigned int free_index;
        /* largest data[] size (not including int size) */
        unsigned int largest_free_space;

	/* unsigned int size - if the last bit is set the data block is used
                               if 0, the rest of the block is free
	   unsigned char data[]
	   unsigned int size
           ... */
        unsigned char data[1];
} PoolBlock;

#define BLOCK_INCREMENT_COUNT 5
typedef struct {
	struct Pool pool;

	unsigned short magic; /* 0xbeef */
	int refcount;

	int num_blocks, used_blocks;
        int first_block_with_space; /* -1 = all used */
	PoolBlock **blocks; /* num_blocks size */

	char name[1]; /* human readable name for blocks - used in statistics.
	                 variable size */
} AllocfreePool;

static struct Pool static_allocfree_pool;

static void pool_allocfree_free(Pool pool, void *mem);

static void pool_block_create(AllocfreePool *apool, unsigned int size)
{
	PoolBlock *block;
        int alloc_size;

	i_assert(size > sizeof(int));

	if (apool->used_blocks >= apool->num_blocks) {
                apool->num_blocks += BLOCK_INCREMENT_COUNT;

		alloc_size = sizeof(PoolBlock *) * apool->num_blocks;
		apool->blocks = apool->blocks == NULL ? malloc(alloc_size) :
			realloc(apool->blocks, alloc_size);
		if (apool->blocks == NULL) {
			i_panic("pool_block_create(): "
				"Out of memory when reallocating %d bytes",
				alloc_size);
		}
	}

        alloc_size = sizeof(PoolBlock)-1 + size;
	block = malloc(alloc_size);
	if (block == NULL) {
		i_panic("pool_block_create(): "
			"Out of memory when allocating %d bytes", alloc_size);
	}

	block->size = size;
	block->free_index = 0;
	block->largest_free_space = size-sizeof(int)-ALLOC_EXTRA_SIZE;
        memset(block->data, 0, sizeof(int));

	if (apool->first_block_with_space == -1)
                apool->first_block_with_space = apool->used_blocks;
	apool->blocks[apool->used_blocks] = block;
	apool->used_blocks++;
}

static int pool_block_get_pos(AllocfreePool *apool, PoolBlock *block)
{
	int pos;

	for (pos = 0; pos < apool->used_blocks; pos++) {
		if (apool->blocks[pos] == block)
			return pos;
	}

        return -1;
}

static void pool_reset_first_free_block(AllocfreePool *apool)
{
	int pos;

	pos = apool->first_block_with_space;
	i_assert(pos >= 0);

	apool->first_block_with_space = -1;
	for (; pos < apool->used_blocks; pos++) {
		if (apool->blocks[pos]->largest_free_space > 0) {
			apool->first_block_with_space = pos;
                        break;
		}
	}
}

static void pool_block_destroy(AllocfreePool *apool, PoolBlock *block)
{
	int pos;

        pos = pool_block_get_pos(apool, block);
	if (pos == -1)
		return;

	memmove(apool->blocks+pos, apool->blocks+pos+1,
		sizeof(PoolBlock *) * (apool->num_blocks-pos-1));
        apool->used_blocks--;

	if (apool->first_block_with_space > pos)
		apool->first_block_with_space--;
	else if (apool->first_block_with_space == pos)
		pool_reset_first_free_block(apool);
        free(block);
}

static PoolBlock *pool_block_find(AllocfreePool *apool, void *mem)
{
        PoolBlock *block;
	int pos;

#ifdef POOL_SAVE_BLOCK
	memcpy(&block, (unsigned char *) mem - sizeof(PoolBlock *),
	       sizeof(PoolBlock *));

	for (pos = 0; pos < apool->used_blocks; pos++) {
		if (apool->blocks[pos] == block)
                        return block;
	}
#else

	/* NOTE: this may be a portability problem, since it compares
	   unrelated pointers. */
	for (pos = 0; pos < apool->used_blocks; pos++) {
                block = apool->blocks[pos];

		if ((unsigned char *) mem >= block->data &&
		    (unsigned char *) mem < block->data + block->size)
                        return block;
	}
#endif

        return NULL;
}

#ifdef POOL_DEBUG
static void pool_block_dump(PoolBlock *block)
{
	unsigned char *mem;
	unsigned int holesize, holesize_real;

	printf("Block: size %d\n", block->size);

	mem = block->data;
	mem2int(mem, holesize);
	while (holesize > 0) {
		holesize_real = mem_size(holesize);
		printf(" - %u %s\n", holesize_real,
		       is_mem_free(holesize) ? " (free)" : "");

		mem += holesize_real + sizeof(int);
		if (mem-block->data == block->size)
			break;

		if (mem-block->data > block->size)
			i_panic("pool_block_alloc() : corrupted pool");

		mem2int(mem, holesize);
	}
}

static void pool_dump(AllocfreePool *apool)
{
	int i;

	printf("Dumping pool: %s\n", apool->name);

	for (i = 0; i < apool->used_blocks; i++)
                pool_block_dump(apool->blocks[i]);
}
#endif

static void *pool_block_alloc(AllocfreePool *apool, PoolBlock *block,
			      unsigned int size)
{
	unsigned char *mem, *alloc;
	unsigned int largest, holesize, holesize_real, avail_size;
        unsigned int alloc_index, next_free_index;

#ifdef POOL_DEBUG
        printf("pool_block_alloc(%s, %d)\n", apool->name, size);
#endif

        size += ALLOC_EXTRA_SIZE;

	/* search for first large enough free space in the block.
	   remember the largest free block so far so if we use the
	   current largest, we don't have to scan the largest one
	   from the beginning. */
        largest = 0;
	mem = block->data + block->free_index;
	mem2int(mem, holesize);
	while (holesize > 0) {
		holesize_real = mem_size(holesize);
		if (holesize_real + sizeof(int)*2 > block->size)
			i_panic("pool_block_alloc() : corrupted pool");

		if (is_mem_free(holesize)) {
			if (size <= holesize_real)
				break;

			if (holesize_real-ALLOC_EXTRA_SIZE > largest)
				largest = holesize_real-ALLOC_EXTRA_SIZE;
		}

		mem += holesize_real + sizeof(int);
		mem2int(mem, holesize);
	}

	avail_size = mem_size(holesize);
	if (avail_size == 0) {
                /* rest of the block is free */
		if ((int) (mem-block->data)+size >= block->size) {
			i_panic("pool_block_alloc(): not enough space "
				"in block (should have been)");
		}

		avail_size = block->size - (int) (mem-block->data) -
			sizeof(int);
	} else if (avail_size-ALLOC_EXTRA_SIZE != block->largest_free_space) {
		/* we didn't use the largest free space in block,
		   so we don't need to scan the rest of the data to
		   search it */
                largest = block->largest_free_space;
	}

	if (avail_size < size+sizeof(int)*3) {
                /* don't bother leaving small holes in the pool */
		size = avail_size;
	}

#ifdef POOL_DEBUG
        if (size == avail_size)
                printf(" - pool is now full\n");
#endif

        /* [i.....] -> [iXXi..] (i = space size, X = data, . = empty space) */
	int2mem(mem, size);
	alloc = mem + sizeof(int);
	alloc_index = (int) (mem-block->data);

#ifdef POOL_SAVE_BLOCK
        memcpy(alloc, &block, sizeof(PoolBlock *));
        alloc += sizeof(PoolBlock *);
#endif

        /* set mem point to beginning of next hole */
	mem += size + sizeof(int);

	if (size < avail_size) {
                /* we didn't use the whole space, mark it unused */
		avail_size = holesize == 0 ? 0 : MEM_FREE_BIT |
			(avail_size - size - sizeof(int));
		int2mem(mem, avail_size);
		next_free_index = (int) (mem-block->data);
	} else if (block->free_index == alloc_index) {
		/* we used the first free hole, get the next one */
		next_free_index = block->size;
		while (mem < block->data+block->size) {
			mem2int(mem, holesize);
			if (holesize == 0) {
				next_free_index = (int) (mem-block->data);
				break;
			}

			holesize_real = mem_size(holesize);
			if (is_mem_free(holesize)) {
				next_free_index =
					(int) (mem-block->data);
				break;
			}

			mem += holesize_real + sizeof(int);
		}
	} else {
		/* just to suppress compiler warnings */
		next_free_index = 0;
	}

         /* update the first free space index */
	if (block->free_index == alloc_index)
		block->free_index = next_free_index;

	if (holesize > 0 && largest < block->largest_free_space) {
		/* we just used the largest space in the block,
		   we'll need to find the next largest one and it
		   could be after the space we just used */
		while (mem < block->data+block->size) {
			mem2int(mem, holesize);
			if (holesize == 0)
                                break;

			holesize_real = mem_size(holesize);
			if (holesize_real +
			    sizeof(int)*2 > block->size)
				i_panic("pool_block_alloc() : corrupted pool");

			if (is_mem_free(holesize) &&
			    holesize_real-ALLOC_EXTRA_SIZE > largest)
				largest = holesize_real-ALLOC_EXTRA_SIZE;

			mem += holesize_real + sizeof(int);
		}
	}

	if (holesize == 0 && mem < block->data+block->size) {
                /* rest of the block is free */
		holesize = block->size - (int) (mem-block->data + sizeof(int));
		if (holesize-ALLOC_EXTRA_SIZE > largest)
			largest = holesize-ALLOC_EXTRA_SIZE;
	}

	block->largest_free_space = largest;
	if (largest == 0)
		pool_reset_first_free_block(apool);

	return alloc;
}

/* Returns the previous block for "mem", or NULL if either there's no
   previous block or if previous block is before any of the free blocks. */
static unsigned char *
pool_block_prev(PoolBlock *block, unsigned char *find_mem)
{
	unsigned char *mem, *next_mem;
        unsigned int holesize;

	if (block->free_index >= (unsigned int) (find_mem-block->data))
		return NULL;

	mem = block->data + block->free_index;
	mem2int(mem, holesize);
	while (holesize > 0) {
		next_mem = mem + mem_size(holesize) + sizeof(int);
		if (next_mem == find_mem)
			return mem;

                mem = next_mem;
		mem2int(mem, holesize);
	}

        return NULL;
}

static void pool_block_free(AllocfreePool *apool, PoolBlock *block,
			    unsigned char *mem)
{
	unsigned char *next_mem, *prev_mem;
	unsigned int holesize, next_holesize, avail_space, prevsize;
	unsigned int next_free_index;
        int pos;

#ifdef POOL_SAVE_BLOCK
        mem -= sizeof(PoolBlock *);
#endif
        mem -= sizeof(int);
	mem2int(mem, holesize);

#ifdef POOL_DEBUG
	printf("pool_block_free(%s, %u)\n", apool->name, mem_size(holesize));
#endif

	if ((holesize & MEM_FREE_BIT) != 0 ||
	    mem_size(holesize) + sizeof(int) > block->size)
		i_panic("pool_block_free() : corrupted pool");

	if ((int) (mem-block->data) + holesize + sizeof(int) >= block->size) {
                /* this is the last space in block */
                holesize = 0;
	} else {
		next_mem = ((unsigned char *) mem) + holesize + sizeof(int);
		mem2int(next_mem, next_holesize);

		if (next_holesize == 0) {
			/* last used space - combine to free space at end */
                        holesize = 0;
		} else if (!is_mem_free(next_holesize)) {
			/* mark the space free */
			holesize |= MEM_FREE_BIT;
		} else {
			/* combine the two free spaces */
			holesize = (mem_size(holesize) + sizeof(int) +
				    mem_size(next_holesize)) | MEM_FREE_BIT;
		}
	}
	int2mem(mem, holesize);

        /* if previous block is free, we can combine the free space */
	prev_mem = pool_block_prev(block, mem);
	if (prev_mem != NULL) {
		mem2int(prev_mem, prevsize);
		if (is_mem_free(prevsize)) {
			if (holesize != 0) {
				holesize = (mem_size(holesize) + sizeof(int) +
					    mem_size(prevsize)) | MEM_FREE_BIT;
			}
			int2mem(prev_mem, holesize);
                        mem = prev_mem;
		}
	}

        /* update largest free space size */
	avail_space = holesize != 0 ? mem_size(holesize) :
		block->size - (int) (mem-block->data + sizeof(int));

#ifdef POOL_FREE_CLEAR
	memset(mem + sizeof(int), POOL_FREE_CLEAR, avail_space);
#elif defined (POOL_SAVE_BLOCK)
	memset(mem + sizeof(int), 0, sizeof(PoolBlock *));
#endif

	if (block->largest_free_space < avail_space-ALLOC_EXTRA_SIZE)
		block->largest_free_space = avail_space-ALLOC_EXTRA_SIZE;

        /* update the first free space index */
        next_free_index = (int) (mem-block->data);
	if (block->free_index > next_free_index)
		block->free_index = next_free_index;

        /* update pool's first block with free space index */
	pos = pool_block_get_pos(apool, block);
	if (apool->first_block_with_space < 0 ||
	    pos < apool->first_block_with_space)
		apool->first_block_with_space = pos;

	if (holesize == 0 && mem == block->data) {
		/* FIXME: the block is completely unused, if there's more
		   than two empty blocks, free them */
	}
}

Pool pool_allocfree_create(const char *name, unsigned int size)
{
        AllocfreePool *apool;

	i_assert(size > sizeof(int));

	apool = calloc(sizeof(AllocfreePool) + strlen(name), 1);
	if (apool == NULL)
		i_panic("pool_create(): Out of memory");

	apool->pool = static_allocfree_pool;
	apool->magic = 0xbeef;
        apool->refcount = 1;

        apool->first_block_with_space = -1;
	pool_block_create(apool, nearest_power(size));

	strcpy(apool->name, name);
	return &apool->pool;
}

#ifdef POOL_CHECK_LEAKS
static const char *get_leak_string(const unsigned char *mem, int size)
{
	int i;

	mem += sizeof(int);

#ifdef POOL_SAVE_BLOCK
        mem += sizeof(PoolBlock *);
        size -= sizeof(PoolBlock *);
#endif

	for (i = 0; i < size; i++) {
		if (mem[i] == '\0')
			return (const char *) mem;

		if ((mem[i] & 0x7f) < 32)
                        break;
	}

        return NULL;
}

static const char *pool_block_count_leaks(PoolBlock *block, int *leak_count,
					  int *leak_size)
{
        const char *leak_string;
	unsigned char *mem;
	unsigned int holesize, holesize_real;

        leak_string = NULL;

	mem = block->data;
	mem2int(mem, holesize);
	while (holesize > 0) {
		holesize_real = mem_size(holesize);
		if (!is_mem_free(holesize)) {
			(*leak_count)++;
			*leak_size += holesize_real;

			if (leak_string == NULL) {
				leak_string = get_leak_string(mem,
							      holesize_real);
			}
		}

		if (holesize_real + sizeof(int)*2 > block->size)
			i_panic("pool_block_count_leaks() : corrupted pool");

		mem += holesize_real + sizeof(int);
		mem2int(mem, holesize);
	}

        return leak_string;
}

static void pool_check_leaks(AllocfreePool *apool)
{
        const char *leak_string;
	int i, leak_count, leak_size;

        leak_string = NULL;
        leak_count = leak_size = 0;
	for (i = 0; i < apool->used_blocks; i++) {
                PoolBlock *block = apool->blocks[i];

		if (block->free_index < block->size) {
			leak_string = pool_block_count_leaks(block, &leak_count,
							     &leak_size);
		}
	}

	if (leak_count > 0) {
		i_warning("Pool '%s' leaked %d allocs with "
			  "total size of %d (%s)",
			  apool->name, leak_count, leak_size,
			  leak_string == NULL ? "" : leak_string);
	}
}
#endif

static void pool_destroy(AllocfreePool *apool)
{
        check_pool(apool);

#ifdef POOL_CHECK_LEAKS
        pool_check_leaks(apool);
#endif

	while (apool->used_blocks > 0)
		pool_block_destroy(apool, apool->blocks[0]);
	free(apool->blocks);
        free(apool->name);
	free(apool);
}

static void pool_allocfree_ref(Pool pool)
{
        AllocfreePool *apool = (AllocfreePool *) pool;

	apool->refcount++;
}

static void pool_allocfree_unref(Pool pool)
{
        AllocfreePool *apool = (AllocfreePool *) pool;

	if (--apool->refcount == 0)
                pool_destroy(apool);
}

static void *pool_allocfree_malloc(Pool pool, unsigned int size)
{
        AllocfreePool *apool = (AllocfreePool *) pool;
        PoolBlock *block;
	void *mem;
        int i, allocsize;

	if (size == 0)
		return NULL;

	if (size > MAX_ALLOC_SIZE)
		i_panic("Trying to allocate too much memory");

	/* allocate only aligned amount of memory so alignment comes
	   always properly */
	size = (size + MEM_ALIGN-1) & ~(MEM_ALIGN-1);

        check_pool(apool);

	/* check if there's enough space in one of the existing blocks */
        block = NULL;
	for (i = 0; i < apool->used_blocks; i++) {
		if (apool->blocks[i]->largest_free_space >= size) {
                        block = apool->blocks[i];
                        break;
		}
	}

	if (block == NULL) {
		/* create new block to pool */
		allocsize = 2*apool->blocks[apool->used_blocks-1]->size;
		if (allocsize-sizeof(int)-ALLOC_EXTRA_SIZE < size)
			allocsize = size*2 + sizeof(int) + ALLOC_EXTRA_SIZE;

		pool_block_create(apool, nearest_power(allocsize));
                block = apool->blocks[apool->used_blocks-1];
	}

	mem = pool_block_alloc(apool, block, size);
	memset(mem, 0, size);

#ifdef POOL_DEBUG
	pool_dump(apool);
#endif
        return mem;
}

static void *pool_allocfree_realloc(Pool pool, void *mem, unsigned int size)
{
        AllocfreePool *apool = (AllocfreePool *) pool;
        unsigned char *mem_size_pos, *oldmem;
	unsigned int memsize;

	if (size == 0) {
		pool_allocfree_free(pool, mem);
		return NULL;
	}

	if (mem == NULL)
                return pool_allocfree_malloc(pool, size);

        check_pool(apool);

        mem_size_pos = (unsigned char *) mem - sizeof(int);
#ifdef POOL_SAVE_BLOCK
	mem_size_pos -= sizeof(PoolBlock *);
#endif

        mem2int(mem_size_pos, memsize);
	if (memsize == size)
                return mem;

	/* FIXME: shrinking could be done more efficiently, also growing
	   might be able to check if it can extend it's current allocation */
        oldmem = mem;
	mem = pool_allocfree_malloc(pool, size);
	memcpy(mem, oldmem, memsize < size ? memsize : size);
        pool_allocfree_free(pool, oldmem);

#ifdef POOL_DEBUG
	pool_dump(apool);
#endif

	if (size > memsize)
		memset((char *) mem + memsize, 0, size-memsize);
        return mem;
}

static void *pool_allocfree_realloc_min(Pool pool, void *mem,
					unsigned int size)
{
        unsigned char *mem_size_pos;
	unsigned int memsize;

	if (mem == NULL)
                return pool_allocfree_malloc(pool, size);

        mem_size_pos = (unsigned char *) mem - sizeof(int);
#ifdef POOL_SAVE_BLOCK
	mem_size_pos -= sizeof(PoolBlock *);
#endif

	mem2int(mem_size_pos, memsize);
	if (size <= memsize)
                return mem;

	return pool_allocfree_realloc(pool, mem, size);
}

static void pool_allocfree_free(Pool pool, void *mem)
{
        AllocfreePool *apool = (AllocfreePool *) pool;
	PoolBlock *block;

        if (mem == NULL)
                return;

        check_pool(apool);

	block = pool_block_find(apool, mem);
	if (block == NULL)
		i_panic("pool_allocfree_free(): invalid memory address");

        pool_block_free(apool, block, mem);

#ifdef POOL_DEBUG
	pool_dump(apool);
#endif
}

static void pool_allocfree_clear(Pool pool)
{
        AllocfreePool *apool = (AllocfreePool *) pool;
	int i;

	apool->first_block_with_space = 0;

	for (i = 0; i < apool->used_blocks; i++) {
		PoolBlock *block = apool->blocks[i];

		block->free_index = 0;
		block->largest_free_space = block->size -
			sizeof(int) - ALLOC_EXTRA_SIZE;
		memset(block->data, 0, sizeof(int));
	}
}

static struct Pool static_allocfree_pool = {
	pool_allocfree_ref,
	pool_allocfree_unref,

	pool_allocfree_malloc,
	pool_allocfree_free,

	pool_allocfree_realloc,
	pool_allocfree_realloc_min,

	pool_allocfree_clear
};

#ifdef POOL_DEBUG
#include <stdlib.h>

void mempool_test(void)
{
	Pool p;
        void *arr[100];
	int i, j;

	memset(arr, 0, sizeof(arr));

	p = pool_create("temp", 32);
	for (i = 0; i < 10000; i++) {
		arr[rand()%100] = p_malloc(p, 4*(rand()%10+1));

		if (rand()%3 == 1) {
			for (j = 0; j < 100; j++) {
				if (arr[j] != NULL)
					p_free_and_null(p, arr[j]);
			}
		}
	}
}
#endif
