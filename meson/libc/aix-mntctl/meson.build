# AIX-only.

if conf.has('HAVE_SYS_VMOUNT_H')
  mntctl_size = cc.run(
    import('fs').read('mntctl-size.c'),
    name: 'reasonable mntctl buffer size',
  )

  if mntctl_size.compiled() and mntctl_size.returncode() == 0
    conf.set(
      'STATIC_MTAB_SIZE',
      mntctl_size.stdout().strip().to_int(),
      description: 'reasonable mntctl buffer size',
    )
  endif
endif
