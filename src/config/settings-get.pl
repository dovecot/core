#!/usr/bin/env perl
use strict;

print '#include "lib.h"'."\n";
print '#include "array.h"'."\n";
print '#include "var-expand.h"'."\n";
print '#include "file-lock.h"'."\n";
print '#include "settings-parser.h"'."\n";
print '#include "all-settings.h"'."\n";
print '#include <stddef.h>'."\n";
print '#include <unistd.h>'."\n";
print '#define CONFIG_BINARY'."\n";
print 'extern buffer_t config_all_services_buf;';

my @services = ();
my %parsers = {};

foreach my $file (@ARGV) {
  my $f;
  open($f, $file) || die "Can't open $file: $@";
  
  my $state = 0;
  my $file_contents = "";
  my $externs = "";
  my $code = "";
  my %funcs;
  my $cur_name = "";
  
  while (<$f>) {
    my $write = 0;
    if ($state == 0) {
      if (/struct .*_settings {/ ||
	  /struct setting_define.*{/ ||
	  /struct .*_default_settings = {/) {
	$state++;
      } elsif (/^struct service_settings (.*) = {/) {
	$state++;
	push @services, $1;
      } elsif (/^(static )?const struct setting_parser_info (.*) = {/) {
	$cur_name = $2;
	$state++ if ($cur_name !~ /^\*default_/);
      } elsif (/^extern const struct setting_parser_info (.*);/) {
	$externs .= "extern const struct setting_parser_info $1;\n";
      } elsif (/\/\* <settings checks> \*\//) {
	$state = 4;
	$code .= $_;
      }

      if (/#define.*DEF/ || /^#undef.*DEF/ || /ARRAY_DEFINE_TYPE.*_settings/) {
	$write = 1;
	$state = 2 if (/\\$/);
      }
    } elsif ($state == 2) {
      $write = 1;
      $state = 0 if (!/\\$/);
    } elsif ($state == 4) {
      $code .= $_;
      $state = 0 if (/\/\* <\/settings checks> \*\//);
    }
    
    if ($state == 1 || $state == 3) {
      if ($state == 1) {
	if (/MEMBER\(module_name\) "(.*)"/) {
	  $parsers{$cur_name} = $1;
	}
	if (/DEFLIST.*".*",(.*)$/) {
	  my $value = $1;
	  if ($value =~ /.*&(.*)\)/) {
	    $parsers{$1} = 0;
	    $externs .= "extern const struct setting_parser_info $1;\n";
	  } else {
	    $state = 3;
	  }
	}
      } elsif ($state == 3) {
	if (/.*&(.*)\)/) {
	  $parsers{$1} = 0;
	}        
      }
      
      $write = 1;
      if (/};/) {
	$state = 0;
      }
    }
  
    $file_contents .= $_ if ($write);
  }
  
  print "/* $file */\n";
  print $externs;
  print $code;
  print $file_contents;

  close $f;
}

print "static struct service_settings *config_all_services[] = {\n";

foreach my $name (@services) {
  print "\t&$name,\n";
}
print "};\n";
print "buffer_t config_all_services_buf = {\n";
print "\tconfig_all_services, sizeof(config_all_services), { 0, }\n";
print "};\n";

print "const struct setting_parser_info *all_default_roots[] = {\n";
foreach my $name (keys %parsers) {
  my $module = $parsers{$name};
  next if (!$module);

  print "\t&".$name.", \n";
}
print "\tNULL\n";
print "};\n";
print "const struct setting_parser_info *const *all_roots = all_default_roots;\n";
