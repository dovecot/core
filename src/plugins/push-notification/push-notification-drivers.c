/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mail-user.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"

static ARRAY(const struct push_notification_driver *) push_notification_drivers;

static bool
push_notification_driver_find(const char *name, unsigned int *idx_r)
{
	unsigned int count, i;
	const struct push_notification_driver *const *drivers;

	drivers = array_get(&push_notification_drivers, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(drivers[i]->name, name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}

	return FALSE;
}

static const struct push_notification_driver *
push_notification_driver_find_class(const char *driver)
{
	const struct push_notification_driver *const *class_p;
	unsigned int idx;

	if (!push_notification_driver_find(driver, &idx))
		return NULL;

	class_p = array_idx(&push_notification_drivers, idx);

	return *class_p;
}

static struct push_notification_driver_config *
push_notification_driver_parse_config(const char *p)
{
	const char **args, *key, *p2, *value;
	struct push_notification_driver_config *config;

	config = t_new(struct push_notification_driver_config, 1);
	config->raw_config = p;

	hash_table_create(&config->config, unsafe_data_stack_pool, 0,
			  str_hash, strcmp);

	if (p == NULL)
		return config;

	args = t_strsplit_spaces(p, " ");

	for (; *args != NULL; args++) {
		p2 = strchr(*args, '=');
		if (p2 != NULL) {
			key = t_strdup_until(*args, p2);
			value = t_strdup(p2 + 1);
		} else {
			key = *args;
			value = "";
		}
		hash_table_update(config->config, key, value);
	}

	return config;
}

int push_notification_driver_init(
	struct mail_user *user, const char *config_in, pool_t pool,
	struct push_notification_driver_user **duser_r)
{
	void *context = NULL;
	const struct push_notification_driver *driver;
	const char *driver_name, *error_r, *p;
	struct push_notification_driver_user *duser;
	int ret;

	/* <driver>[:<driver config>] */
	p = strchr(config_in, ':');
	if (p == NULL)
		driver_name = config_in;
	else
		driver_name = t_strdup_until(config_in, p);

	driver = push_notification_driver_find_class(driver_name);
	if (driver == NULL) {
		i_error("Unknown push notification driver: %s", driver_name);
		return -1;
	}

	if (driver->v.init != NULL) {
		T_BEGIN {
			struct push_notification_driver_config *config;

			config = push_notification_driver_parse_config(
					(p == NULL) ? p : p + 1);
			ret = driver->v.init(config, user, pool,
					     &context, &error_r);

			hash_table_destroy(&config->config);
		} T_END;

		if (ret < 0) {
			i_error("%s: %s", driver_name, error_r);
			return -1;
		}
	}

	duser = p_new(pool, struct push_notification_driver_user, 1);
	duser->context = context;
	duser->driver = driver;

	*duser_r = duser;

	return 0;
}

void push_notification_driver_cleanup_all(void)
{
	const struct push_notification_driver *const *driver;

	/* Loop through driver list and perform global cleanup tasks. We may not
	   have used all drivers in this plugin/worker, but the cleanup hooks
	   are designed to ignore these unused drivers. */
	array_foreach(&push_notification_drivers, driver) {
		if ((*driver)->v.cleanup != NULL)
			(*driver)->v.cleanup();
	}
}

void ATTR_FORMAT(3, 4)
push_notification_driver_debug(const char *label, struct mail_user *user,
			       const char *fmt, ...)
{
	va_list args;

	T_BEGIN {
		va_start(args, fmt);
		e_debug(user->event, "%s%s", label,
			t_strdup_vprintf(fmt, args));
		va_end(args);
	} T_END;
}

void push_notification_driver_register(
	const struct push_notification_driver *driver)
{
	unsigned int idx;

	if (!array_is_created(&push_notification_drivers))
		i_array_init(&push_notification_drivers, 4);

	if (push_notification_driver_find(driver->name, &idx)) {
		i_panic("push_notification_driver_register(%s): "
			"duplicate driver", driver->name);
	}

	array_push_back(&push_notification_drivers, &driver);
}

void push_notification_driver_unregister(
	const struct push_notification_driver *driver)
{
	unsigned int idx;

	if (!push_notification_driver_find(driver->name, &idx)) {
		i_panic("push_notification_driver_register(%s): "
			"unknown driver", driver->name);
	}

	if (array_is_created(&push_notification_drivers)) {
		array_delete(&push_notification_drivers, idx, 1);

		if (array_is_empty(&push_notification_drivers))
			array_free(&push_notification_drivers);
	}
}
