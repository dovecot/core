ext_sendfile = cc.find_library('sendfile', required: false)
have_sendfile_func = conf.get('HAVE_SENDFILE', 0) == 1
sendfile_style = 'Unknown'

fs = import('fs')

# Solaris sendfile() lives in libsendfile.
if ext_sendfile.found() and cc.has_function('sendfile', dependencies: ext_sendfile)
  conf.set('HAVE_SOLARIS_SENDFILE', true)
  sendfile_style = 'Solaris'
elif have_sendfile_func or ext_sendfile.found()
  if cc.links(
    fs.read('sendfile-linux.c'),
    dependencies: ext_sendfile,
    name: 'Linux-compatible sendfile()',
  )
    conf.set10('HAVE_LINUX_SENDFILE', true, description: 'Linux-compatible sendfile')
    sendfile_style = 'Linux'
  elif cc.links(
    fs.read('sendfile-freebsd.c'),
    dependencies: ext_sendfile,
    name: 'FreeBSD-compatible sendfile()',
  )
    conf.set10('HAVE_FREEBSD_SENDFILE', true, description: 'FreeBSD-compatible sendfile')
    sendfile_style = 'FreeBSD'
  endif
endif

summary(
  {
    'sendfile Library' : ext_sendfile,
    'sendfile Function' : have_sendfile_func,
    'sendfile Style' : sendfile_style,
  },
  bool_yn: true,
  section: 'Features',
)
