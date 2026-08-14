#include <stdio.h>
#include <stdlib.h>
#include <sys/vmount.h>

int main(void)
{
	int size, count;
	char *m;

	if ((count = mntctl(MCTL_QUERY, sizeof(size), &size)) != 0 ||
	    !(m = malloc(size)) ||
	    (count = mntctl(MCTL_QUERY, size, m)) <= 0)
		return 1;

	/* room for 5 mounts more */
	printf("%d\n", (size * (count + 5)) / count & ~1);
	return 0;
}
