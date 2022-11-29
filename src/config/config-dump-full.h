#ifndef CONFIG_DUMP_FULL
#define CONFIG_DUMP_FULL

enum config_dump_full_dest {
	CONFIG_DUMP_FULL_DEST_RUNDIR,
	CONFIG_DUMP_FULL_DEST_TEMPDIR,
	CONFIG_DUMP_FULL_DEST_STDOUT,
};

int config_dump_full(enum config_dump_full_dest dest,
		     const char **import_environment_r);

#endif
