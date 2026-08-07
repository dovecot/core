# TODO: Autoconf also resolves systemdsystemunitdir from the systemd .pc file and installs
# the unit files there. That belongs with the src/master port.

ext_systemd = dependency('libsystemd', required: get_option('systemd'))

conf.set(
  'HAVE_LIBSYSTEMD',
  ext_systemd.found(),
  description: 'Have libsystemd',
)

summary({'systemd': ext_systemd}, section: 'Features')
