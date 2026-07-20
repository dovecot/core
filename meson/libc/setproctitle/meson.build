setproctitle_prefix = libc_prefix

if ext_bsd.found()
  setproctitle_prefix += '#include <bsd/unistd.h>\n'
endif

conf.set(
  'HAVE_SETPROCTITLE',
  cc.has_function(
    'setproctitle',
    prefix: setproctitle_prefix,
    dependencies: ext_bsd,
  ),
)

# PROCTITLE_HACK is the argv-rewriting fallback, enabled by default on Linux and macOS
# regardless of setproctitle().
conf.set('PROCTITLE_HACK', system in ['linux', 'darwin'])
