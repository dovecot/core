/* simple checkpassword wrapper to send userdb data back to dovecot-auth */

#include "lib.h"
#include "str.h"
#include "write-full.h"

#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	string_t *str;
	const char *user, *home, *authorized;
	const char *extra_env, *key, *value, *const *tmp;
	bool uid_found = FALSE, gid_found = FALSE;

	lib_init();
	str = t_str_new(1024);

	user = getenv("USER");
	if (user != NULL) {
		if (strchr(user, '\t') != NULL) {
			i_error("checkpassword: USER contains TAB");
			return 1;
		}
		str_printfa(str, "user=%s\t", user);
	}

	home = getenv("HOME");
	if (home != NULL) {
		if (strchr(home, '\t') != NULL) {
			i_error("checkpassword: HOME contains TAB");
			return 1;
		}
		str_printfa(str, "userdb_home=%s\t", home);
	}

	extra_env = getenv("EXTRA");
	if (extra_env != NULL) {
		for (tmp = t_strsplit(extra_env, " "); *tmp != NULL; tmp++) {
			value = getenv(*tmp);
			if (value != NULL) {
				key = t_str_lcase(*tmp);
				if (strcmp(key, "userdb_uid") == 0)
					uid_found = TRUE;
				else if (strcmp(key, "userdb_gid") == 0)
					gid_found = TRUE;
				str_printfa(str, "%s=%s\t", key, value);
			}
		}
	}
	if (!uid_found)
		str_printfa(str, "userdb_uid=%s\t",  dec2str(getuid()));
	if (!gid_found)
		str_printfa(str, "userdb_gid=%s\t",  dec2str(getgid()));

	if (write_full(4, str_data(str), str_len(str)) < 0) {
		i_error("checkpassword: write_full() failed: %m");
		exit(111);
	}
	authorized = getenv("AUTHORIZED");
	return authorized != NULL && strcmp(authorized, "2") == 0 ? 2 : 0;
}
