try_libc_functions = [
  'backtrace_symbols',
  'bzero',
  'clearenv',
  'cpuset_getaffinity',
  'dirfd',
  'epoll_create',
  'explicit_bzero',
  'explicit_memset',
  'fallocate',
  'flock',
  'getmntent',
  'getmntinfo',
  'getpeereid',
  'getpeerucred',
  'glob',
  'gmtime_r',
  'inotify_init',
  'kevent',
  'kqueue',
  'localtime_r',
  'malloc_usable_size',
  'memrchr',
  'memset_s',
  'mmap',
  'poll',
  'posix_fadvise',
  'pread',
  'quotactl',
  'sched_getaffinity',
  'select',
  'sendfile',
  'sendfile64',
  'setpriority',
  'setresgid',
  'timegm',
  'walkcontext',
]

foreach func : try_libc_functions
  symbol = func.to_upper().underscorify()

  have_function = cc.has_function(func, prefix : libc_prefix)
  if have_function
    conf.set10(f'HAVE_@symbol@', true)
  endif
endforeach
