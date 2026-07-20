## Select ioloop method

fs = import('fs')

# IO loop: 'best' tries each method in turn and falls back to select() which is always
# available.
ioloop = get_option('ioloop')

if ioloop in ['best', 'epoll'] and conf.get('HAVE_EPOLL_CREATE', 0) == 1 and \
   cc.run(fs.read('epoll.c'), name: 'epoll()').returncode() == 0
  conf.set10('IOLOOP_EPOLL', true)
  ioloop = 'epoll'
elif ioloop in ['best', 'kqueue'] and conf.get('HAVE_KQUEUE', 0) == 1 and \
     conf.get('HAVE_KEVENT', 0) == 1
  conf.set10('IOLOOP_KQUEUE', true)
  ioloop = 'kqueue'
elif ioloop in ['best', 'poll'] and conf.get('HAVE_POLL', 0) == 1
  conf.set10('IOLOOP_POLL', true)
  ioloop = 'poll'
elif ioloop in ['best', 'select']
  conf.set10('IOLOOP_SELECT', true)
  ioloop = 'select'
else
  error(f'@ioloop@ ioloop requested but it is not available')
endif

# Filesystem notification method: 'best' tries inotify first and only considers kqueue
# when it is also the selected ioloop, then fallback to no fs notification at all.
notify = get_option('notify')

build_imap_hibernate = false
if notify in ['best', 'inotify'] and conf.get('HAVE_INOTIFY_INIT', 0) == 1
  conf.set10('IOLOOP_NOTIFY_INOTIFY', true)
  notify = 'inotify'

  conf.set10('BUILD_IMAP_HIBERNATE', true)
  build_imap_hibernate = true
elif ((notify == 'best' and ioloop == 'kqueue') or notify == 'kqueue') and \
     conf.get('HAVE_KQUEUE', 0) == 1 and conf.get('HAVE_KEVENT', 0) == 1
  conf.set10('IOLOOP_NOTIFY_KQUEUE', true)
  notify = 'kqueue'
elif notify in ['best', 'none']
  conf.set10('IOLOOP_NOTIFY_NONE', true)
  notify = 'none'
else
  error(f'@notify@ notify requested but is not available')
endif

summary(
  {
    'ioloop' : ioloop,
    'notify' : notify,
    'IMAP hibernate' : build_imap_hibernate,
  },
  bool_yn: true,
  section: 'Features',
)
