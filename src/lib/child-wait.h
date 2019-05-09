#ifndef CHILD_WAIT_H
#define CHILD_WAIT_H

struct child_wait_status {
	struct child_wait *wait;

	pid_t pid;
	int status;
};

typedef void child_wait_callback_t(const struct child_wait_status *status,
				   void *context);

struct child_wait *
child_wait_new_with_pid(pid_t pid, child_wait_callback_t *callback,
			void *context) ATTR_NULL(3);
#define child_wait_new_with_pid(pid, callback, context) \
	child_wait_new_with_pid(pid - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct child_wait_status *status, typeof(context))), \
	(child_wait_callback_t *)callback, context)
#define child_wait_new(callback, context) \
	child_wait_new_with_pid((pid_t)-1, callback, context)
void child_wait_free(struct child_wait **wait);

void child_wait_add_pid(struct child_wait *wait, pid_t pid);
void child_wait_remove_pid(struct child_wait *wait, pid_t pid);

void child_wait_switch_ioloop(void);

void child_wait_init(void);
void child_wait_deinit(void);

#endif
