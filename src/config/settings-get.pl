#!/usr/bin/env perl
use strict;
use warnings;

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
my %parsers = ();

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
	$state = "copy-to-end-of-block";
      } elsif (/^struct service_settings (.*) = \{/) {
	$state = "copy-to-end-of-block";
	push @services, $1;
      } elsif (/^const struct setting_keyvalue (.*_defaults)\[\] = \{/) {
        $service_defaults{$1} = 1;
	$state = "copy-to-end-of-block";
      } elsif (/^const struct setting_parser_info (.*) = \{/) {
        my $cur_name = $1;
        $parsers{$cur_name} = 1;
        if ($linked_file) {
          $externs .= "extern const struct setting_parser_info $cur_name;\n";
	}
	$state = "copy-to-end-of-block";
      } elsif (/^extern const struct setting_parser_info (.*);/) {
	$parsers{$1} = 1;
	$externs .= "extern const struct setting_parser_info $1;\n";
      } elsif (/\/\* <settings checks> \*\//) {
	$state = "copy-to-end-of-settings-checks";
	$code .= $_;
      }
      
      if (/#define.*DEF/ || /^#undef.*DEF/ || /ARRAY_DEFINE_TYPE.*_settings/) {
	$write = 1;
	$state = "copy-to-end-of-macro" if (/\\$/);
      }
    } elsif ($state eq "copy-to-end-of-macro") {
      $write = 1;
      $state = "root" if (!/\\$/);
    } elsif ($state eq "copy-to-end-of-settings-checks") {
      $code .= $_;
      $state = "root" if (/\/\* <\/settings checks> \*\//);
    }

    if ($state eq "copy-to-end-of-block") {
      s/^static const (struct master_settings master_default_settings)/$1/;

      $write = 1;
      if (/};/) {
	$state = "root";
      }
    }
  
    $file_contents .= $_ if ($write);
  }
  
  print "/* $file */\n";
  print $externs;
  if (!$linked_file) {
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
print "static const struct config_service config_default_services[] = {\n";
@services = sort { service_name($a) cmp service_name($b) } @services;
for (my $i = 0; $i < scalar(@services); $i++) {
  my $defaults = "NULL";
  if (defined($service_defaults{$services[$i]."_defaults"})) {
    $defaults = $services[$i]."_defaults";
  }
  print "\t{ &".$services[$i].", $defaults },\n";
}
print "\t{ NULL, NULL }\n";
print "};\n";

print "const struct setting_parser_info *all_default_roots[] = {\n";
foreach my $name (sort(keys %parsers)) {
  print "\t&".$name.", \n";
}
print "\tNULL\n";
print "};\n";
print "const struct setting_parser_info *const *all_roots = all_default_roots;\n";
print "const struct config_service *config_all_services = config_default_services;\n";
