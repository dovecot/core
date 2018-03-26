#ifndef GLOBAL_MEMORY_H
#define GLOBAL_MEMORY_H

extern size_t global_used_memory;

void global_memory_alloc(size_t size);
void global_memory_free(size_t size);

#endif
