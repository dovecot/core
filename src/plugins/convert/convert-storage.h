#ifndef __CONVERT_STORAGE_H
#define __CONVERT_STORAGE_H

struct convert_settings {
	const char *user;
	const char *home;
	bool skip_broken_mailboxes;
	bool skip_dotfiles;
	char alt_hierarchy_char;
};

int convert_storage(const char *source_data, const char *dest_data,
		    const struct convert_settings *set);

#endif
