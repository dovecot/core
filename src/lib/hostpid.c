/*
 hostpid.c : Easy way to get our own hostname and pid

    Copyright (c) 2002 Timo Sirainen

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

#include "lib.h"
#include "hostpid.h"

#include <unistd.h>

const char *my_hostname = NULL;
const char *my_pid = NULL;

void hostpid_init(void)
{
	static char hostname[256], pid[100];

	if (my_hostname == NULL) {
		hostname[sizeof(hostname)-1] = '\0';
		if (gethostname(hostname, sizeof(hostname)-1) == -1)
			strcpy(hostname, "unknown");

		my_hostname = hostname;
	}

	if (my_pid == NULL) {
		i_snprintf(pid, sizeof(pid), "%lu", (unsigned long) getpid());
		my_pid = pid;
	}
}
