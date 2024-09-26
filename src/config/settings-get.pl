#!/usr/bin/env perl
use strict;
use warnings;
use 5.008;

print "/* WARNING: THIS FILE IS GENERATED - DO NOT PATCH!\n";
print "   It's not enough alone in any case, because the defaults may be\n";
print "   coming from the individual *-settings.c in some situations. If you\n";
print "   wish to modify defaults, change the other *-settings.c files and\n";
print "   just delete this file. This file will be automatically regenerated\n";
print "   by make. (This file is distributed in the tarball only because some\n";
print "   systems might not have Perl installed.) */\n";
print '#include "lib.h"'."\n";
print '#include "array.h"'."\n";
print '#include "str.h"'."\n";
print '#include "ipwd.h"'."\n";
print '#include "var-expand.h"'."\n";
print '#include "file-lock.h"'."\n";
print '#include "fsync-mode.h"'."\n";
print '#include "hash-format.h"'."\n";
print '#include "net.h"'."\n";
print '#include "unichar.h"'."\n";
print '#include "hash-method.h"'."\n";
print '#include "settings.h"'."\n";
print '#include "settings-parser.h"'."\n";
print '#include "message-header-parser.h"'."\n";
print '#include "imap-urlauth-worker-common.h"'."\n";
print '#include "all-settings.h"'."\n";
print '#include <unistd.h>'."\n";
print '#define CONFIG_BINARY'."\n";

my @services = ();
my %service_defaults = ();
my %infos = ();

my $linked_file = 0;
foreach my $file (@ARGV) {
  if ($file eq "--") {
    $linked_file = 1;
    next;
  }
  my $f;
  open($f, $file) || die "Can't open $file: $@";
  
  my $state = "root";
  my $file_contents = "";
  my $externs = "";
  my $code = "";
  
  while (<$f>) {
    my $write = 0;
    if ($state eq "root") {
      if (/struct .*_settings \{/ ||
          /struct setting_define.*\{/ ||
          /struct .*_default_settings = \{/) {
        # settings-related structure - copy.
        $state = "copy-to-end-of-block";
      } elsif (/^struct service_settings (.*) = \{/) {
        # service settings - copy and add to list of services.
        $state = "copy-to-end-of-block";
        push @services, $1;
      } elsif (/^const struct setting_keyvalue (.*_defaults)\[\] = \{/) {
        # service's default settings as keyvalues - copy and add to list of
        # defaults.
        $service_defaults{$1} = 1;
        $state = "copy-to-end-of-block";
      } elsif (/^const struct setting_parser_info (.*) = \{/) {
        # info structure for settings
        my $cur_name = $1;
        $infos{$cur_name} = 1;
        # Add forward declaration for the info struct. This may be needed by
        # the ext_check() functions.
        $externs .= "extern const struct setting_parser_info $cur_name;\n";
        $state = "copy-to-end-of-block";
      } elsif (/\/\* <settings checks> \*\//) {
        # Anything inside <settings check> ... </settings check> is copied.
        $state = "copy-to-end-of-settings-checks";
        $code .= $_;
      }
      
      if (/#define.*DEF/ || /^#undef.*DEF/ || /ARRAY_DEFINE_TYPE.*_settings/) {
        # macro for setting_define { ... } - copy.
        $write = 1;
        if (/\\$/) {
          # multi-line macro
          $state = "copy-to-end-of-macro";
        }
      }
    } elsif ($state eq "copy-to-end-of-macro") {
      # Continue copying macro until the line doesn't end with '\'
      $write = 1;
      $state = "root" if (!/\\$/);
    } elsif ($state eq "copy-to-end-of-settings-checks") {
      $code .= $_;
      $state = "root" if (/\/\* <\/settings checks> \*\//);
    }

    if ($state eq "copy-to-end-of-block") {
      $write = 1;
      if (/};/) {
        $state = "root";
      }
    }
  
    $file_contents .= $_ if ($write);
  }
  
  print "/* $file */\n";
  print $externs;
  if ($linked_file) {
    # The code and contents are already linked via libdovecot.so. Don't add
    # them again.
  } else {
    print $code;
    print $file_contents;
  }

  close $f;
}

sub service_name {
  $_ = $_[0];
  return $1 if (/^(.*)_service_settings$/);
  die "unexpected service name $_";
}
# Write an array of default services and their default settings.
print "static const struct config_service config_default_services[] = {\n";
@services = sort { service_name($a) cmp service_name($b) } @services;
for (my $i = 0; $i < scalar(@services); $i++) {
  my $defaults = "NULL";
  if (defined($service_defaults{$services[$i]."_defaults"})) {
    $defaults = $services[$i]."_defaults";
  }
  my $ignore_macros = uc $services[$i];
  $ignore_macros =~ s/_SETTINGS$//;
  print "#ifndef IGNORE_$ignore_macros\n";
  print "\t{ &".$services[$i].", $defaults },\n";
  print "#endif\n"
}
print "\t{ NULL, NULL }\n";
print "};\n";

# Write a list of all settings infos.
print "const struct setting_parser_info *all_default_infos[] = {\n";
foreach my $name (sort(keys %infos)) {
  print "\t&".$name.", \n";
}
print "\tNULL\n";
print "};\n";
print "const struct setting_parser_info *const *all_infos = all_default_infos;\n";
print "const struct config_service *config_all_services = config_default_services;\n";
