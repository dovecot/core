/* simple checkpassword wrapper to send userdb data back to dovecot-auth */

#include "lib.h"
#include "str.h"
#include "write-full.h"

#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	string_t *str;

	lib_init();
	str = t_str_new(1024);

	str_printfa(str, "USER=%s\nHOME=%s\nSHELL=%s\nUID=%s\nGID=%s\n\n",
		    getenv("USER"), getenv("HOME"), getenv("SHELL"),
		    dec2str(getuid()), dec2str(getgid()));

	if (write_full(4, str_data(str), str_len(str)) < 0) {
		i_error("write_full() failed: %m");
		exit(111);
	}
	return 0;
}
