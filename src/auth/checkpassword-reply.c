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

	if (strchr(getenv("USER"), '\t') != NULL) {
		i_error("USER contains TAB");
		return 1;
	}
	if (strchr(getenv("HOME"), '\t') != NULL) {
		i_error("HOME contains TAB");
		return 1;
	}

	str_printfa(str, "userdb_user=%s\t"
		    "userdb_home=%s\t"
		    "userdb_uid=%s\t"
		    "userdb_gid=%s\t",
		    getenv("USER"), getenv("HOME"),
		    dec2str(getuid()), dec2str(getgid()));

	if (write_full(4, str_data(str), str_len(str)) < 0) {
		i_error("write_full() failed: %m");
		exit(111);
	}
	return 0;
}
