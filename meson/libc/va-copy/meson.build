fs = import('fs')

prog_template = fs.read('check-va_copy.c')

if cc.run(prog_template.format('va_copy'), name: 'va_copy').returncode() == 0
  conf.set('VA_COPY', 'va_copy')
elif cc.run(prog_template.format('__va_copy'), name: '__va_copy').returncode() == 0
  conf.set('VA_COPY', '__va_copy')
else
  error('Cannot use va_copy or __va_copy')
endif
