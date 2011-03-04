/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fd-close-on-exec.h"
#include "dup2-array.h"

#include <unistd.h>

void dup2_append(ARRAY_TYPE(dup2) *dups, int fd_src, int fd_dest)
{
	struct dup2 d;

	i_assert(fd_src >= 0);
	i_assert(fd_dest >= 0);

	d.fd_src = fd_src;
	d.fd_dest = fd_dest;
	array_append(dups, &d, 1);
}

int dup2_array(ARRAY_TYPE(dup2) *dups_arr)
{
	struct dup2 *dups;
	bool *moved, moves;
	unsigned int i, j, count, conflict;
	int fd;

	dups = array_get_modifiable(dups_arr, &count);

	moved = t_new(bool, count);
	for (;;) {
		conflict = count;
		moves = FALSE;
		for (i = 0; i < count; i++) {
			if (moved[i])
				continue;

			for (j = 0; j < count; j++) {
				if (dups[j].fd_src == dups[i].fd_dest &&
				    !moved[j]) {
					conflict = j;
					break;
				}
			}

			if (j == count) {
				/* no conflicts, move it */
				moved[i] = TRUE;
				moves = TRUE;
				if (dup2(dups[i].fd_src, dups[i].fd_dest) < 0) {
					i_error("dup2(%d, %d) failed: %m",
						dups[i].fd_src,
						dups[i].fd_dest);
					return -1;
				}
			}
		}
		if (conflict == count)
			break;

		if (moves) {
			/* it's possible that the conflicting fd was
			   moved already. try again. */
			continue;
		}

		/* ok, we have to dup() */
		fd = dup(dups[conflict].fd_src);
		if (fd == -1) {
			i_error("dup(%d) failed: %m", dups[conflict].fd_src);
			return -1;
		}
		fd_close_on_exec(fd, TRUE);
                dups[conflict].fd_src = fd;
	}
	return 0;
}

