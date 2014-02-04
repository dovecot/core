/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict-private.h"

void dict_drivers_register_builtin(void)
{
	dict_driver_register(&dict_driver_client);
	dict_driver_register(&dict_driver_file);
	dict_driver_register(&dict_driver_fs);
	dict_driver_register(&dict_driver_memcached);
	dict_driver_register(&dict_driver_memcached_ascii);
	dict_driver_register(&dict_driver_redis);
}

void dict_drivers_unregister_builtin(void)
{
	dict_driver_unregister(&dict_driver_client);
	dict_driver_unregister(&dict_driver_file);
	dict_driver_unregister(&dict_driver_fs);
	dict_driver_unregister(&dict_driver_memcached);
	dict_driver_unregister(&dict_driver_memcached_ascii);
	dict_driver_unregister(&dict_driver_redis);
}
