#ifndef DUP2_ARRAY_H
#define DUP2_ARRAY_H

struct dup2 {
	int fd_src, fd_dest;
};
ARRAY_DEFINE_TYPE(dup2, struct dup2);

void dup2_append(ARRAY_TYPE(dup2) *dups, int fd_src, int fd_dest);

int dup2_array(ARRAY_TYPE(dup2) *dups);

#endif
