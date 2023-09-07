/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "mail-user.h"
#include "settings.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-settings.h"

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

static bool
push_notification_driver_identify(struct mail_user *user, const char *name,
				  const struct push_notification_driver **driver_r,
				  const char **error_r)
{
	struct push_notification_settings *set;
	unsigned int idx;
	if (settings_get_filter(user->event, PUSH_NOTIFICATION_SETTINGS_FILTER_NAME,
				name, &push_notification_setting_parser_info,
				0, &set, error_r) < 0)
		return FALSE;

	bool ret = FALSE;
	if (push_notification_driver_find(set->driver, &idx)) {
		*driver_r = array_idx_elem(&push_notification_drivers, idx);
		ret = TRUE;
	}
	settings_free(set);

	if (!ret)
		*error_r = "Name does not match any registered drivers";

	return ret;
}

int push_notification_driver_init(
	struct mail_user *user, const char *config_in, pool_t pool,
	struct push_notification_driver_user **duser_r)
{
	void *context = NULL;
	const struct push_notification_driver *driver;
	const char *error;
	struct push_notification_driver_user *duser;
	int ret;

	bool found_driver = push_notification_driver_identify(user, config_in,
							      &driver, &error);
	if (!found_driver) {
		e_error(user->event,
			"Unable to identify push notification driver '%s': %s",
			config_in, error);
		return -1;
	}

	if (driver->v.init != NULL) {
		T_BEGIN {
			ret = driver->v.init(user, pool, config_in, &context,
					     &error);
		} T_END_PASS_STR_IF(ret < 0, &error);

		if (ret < 0) {
			e_error(user->event, "%s: %s", driver->name,
				error);
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
	const struct push_notification_driver *driver;

	/* Loop through driver list and perform global cleanup tasks. We may not
	   have used all drivers in this plugin/worker, but the cleanup hooks
	   are designed to ignore these unused drivers. */
	array_foreach_elem(&push_notification_drivers, driver) {
		if (driver->v.cleanup != NULL)
			driver->v.cleanup();
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
