if get_option('hardening')
  probe = import('fs').read('probe.c')
  msg = 'Hardening requested but @0@ (@1@) does not support @2@'

  # Hardening flags must reach every project language: some targets like the fuzzers are
  # linked with C++ so arguments must reach those too.
  compilers = {'c': cc, 'cpp': cxx}

  # --- Read-only Global Offset Table ---
  z_relro = '-Wl,-z,relro'
  z_now = '-Wl,-z,now'
  z_both = '-Wl,-z,relro,-z,now'

  foreach lang, compiler : compilers
    if compiler.has_link_argument(z_both)
      add_project_link_arguments(z_both, language: lang)
    elif compiler.has_link_argument(z_relro) and compiler.has_link_argument(z_now)
      add_project_link_arguments([z_relro, z_now], language: lang)
    else
      warning(msg.format(compiler.get_id(), lang, 'relro'))
    endif
  endforeach

  # --- Fortify Source ---
  u_fortify_source = '-U_FORTIFY_SOURCE'
  d_fortify_source = '-D_FORTIFY_SOURCE=2'

  # _FORTIFY_SOURCE needs an optimizing build, otherwise glibc will disable it. The debug
  # buildtype compiles with -Og (meson/cflags) so only skip unoptimized builds.
  if get_option('optimization') in ['plain', '0'] and get_option('buildtype') != 'debug'
    message(f'Skipping @d_fortify_source@ because it requires an optimizing build')
  else
    foreach lang, compiler : compilers
      if compiler.has_argument(u_fortify_source) and compiler.has_argument(d_fortify_source)
        add_project_arguments([u_fortify_source, d_fortify_source], language: lang)
      else
        warning(msg.format(compiler.get_id(), lang, d_fortify_source))
      endif
    endforeach
  endif

  # --- Retpoline ---
  retpoline = get_option('hardening-retpoline')
  if retpoline not in ['none', 'keep']
    # Treat `none` and `keep` as the same, due to `keep` being GCC's default. This avoids
    # warnings on platforms that don't support the flags.

    retpoline_args = [
      f'-mfunction-return=@retpoline@',
      f'-mindirect-branch=@retpoline@',
    ]

    foreach lang, compiler : compilers
      foreach arg : retpoline_args
        if compiler.links(probe, args: arg, name: f'@arg@ for @lang@')
          add_project_arguments(arg, language: lang)
        else
          warning(msg.format(compiler.get_id(), lang, arg))
        endif
      endforeach
    endforeach
  endif

  # --- Control-flow Protection ---
  fcf_protection = get_option('hardening-fcf-protection')
  if fcf_protection != 'none'
    arg = f'-fcf-protection=@fcf_protection@'
    foreach lang, compiler : compilers
      if compiler.links(probe, args: arg, name: f'@arg@ for @lang@')
        add_project_arguments(arg, language: lang)
      else
        error(msg.format(compiler.get_id(), lang, arg))
      endif
    endforeach
  endif

  # --- SLS Mitigation ---
  sls_mitigation = get_option('hardening-sls')
  if sls_mitigation != 'none'
    arg = f'-mharden-sls=@sls_mitigation@'
    foreach lang, compiler : compilers
      if compiler.links(probe, args: arg, name: f'@arg@ for @lang@')
        add_project_arguments(arg, language: lang)
      else
        error(msg.format(compiler.get_id(), lang, arg))
      endif
    endforeach
  endif

  # --- Stack Protector ----
  stack_protector = get_option('hardening-stack-protector')
  if stack_protector != 'off'
    arg = '-fstack-protector'
    arg_strong = '-fstack-protector-strong'

    # Prefer -fstack-protector-strong and fallback to -fstack-protector.

    foreach lang, compiler : compilers
      if stack_protector in ['auto', 'strong'] and compiler.links(probe, args: arg_strong, name: f'@arg_strong@ for @lang@')
        add_project_arguments(arg_strong, language: lang)
      elif stack_protector == 'strong'
        error(msg.format(compiler.get_id(), lang, arg_strong))
      elif stack_protector in ['auto', 'normal'] and compiler.links(probe, args: arg, name: f'@arg@ for @lang@')
        add_project_arguments(arg, language: lang)
      elif stack_protector == 'normal'
        error(msg.format(compiler.get_id(), lang, arg))
      elif stack_protector == 'auto'
        # `off` never gets here and `strong`/`normal` error out above, so `auto` is the
        # only value left: degrade like relro and _FORTIFY_SOURCE do.
        warning(msg.format(compiler.get_id(), lang, f'@arg_strong@ and @arg@'))
      endif
    endforeach
  endif
endif
