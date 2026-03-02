#!/usr/bin/perl -w
#
#
# SYNTAX:
#   notify_by_email [-t] [-d]
#
# DESCRIPTION:
#	Sends email using template
#   -t for test mode, so just print out the email. Use utils/test_notifications to set envvars
#   -d for debug to print all environment variables to a temporary file for debugging purposes
#
# LICENCE:
#    Copyright (C) 2003-2023 Opsview Limited. All rights reserved
#
#    This file is part of Opsview
#
#

use warnings;
use strict;

BEGIN {

    # If not run from a terminal (e.g. by Nagios) then process can appear
    # to time out due to writing to STDOUT/STDERR.  This is probably because
    # either nagios doesnt read from the process or blocks the output which
    # can cause a hang.  To cope with this redirect output to /dev/null
    # We also ignore if HUDSON_URL is set for automated testing
    if ( !( -t || $ENV{HUDSON_URL} ) ) {
        open( STDERR, '>', '/dev/null' );
        open( STDOUT, '>', '/dev/null' );
    }
}

use lib "/opt/opsview/monitoringscripts/lib", "/opt/opsview/perl/lib/perl5", "/opt/opsview/corelibs/libs";

use Opsview::Utils::NotificationTemplate;
use Getopt::Std;
use HTML::TreeBuilder;
use HTML::FormatText;
use MIME::Base64;
use Opsview::Schema;
use Runtime::Schema;

my $opts = {};
getopts( "tde:", $opts ) or die "Invalid args";

if ( $opts->{d} ) {
    open D, ">>", "/tmp/notify_by_email.debug";
    print D scalar localtime, $/;
    print D $_ . "=" . $ENV{$_} . $/ for sort keys %ENV;
    print D $/;
    close D;
}

my $email;
if ( $ENV{NAGIOS_CONTACTEMAIL} ) {
    $email = $ENV{NAGIOS_CONTACTEMAIL};
}
elsif ( $ENV{OPSVIEW_CONTACTEMAIL} ) {
    $email = $ENV{OPSVIEW_CONTACTEMAIL};
}

unless ($email) {
    die "Need NAGIOS_CONTACTEMAIL or OPSVIEW_CONTACTEMAIL to send emails";
}

my $default_templates = {
    "nagios"  => "com.opsview.notificationmethods.email.tt",
    "opsview" => "com.opsview.notificationmethods.email.opsview.tt",
};

my $output           = "";
my $error            = "";
my $notificationtype = $ENV{OPSVIEW_OBJECTTYPE} ? "opsview" : "nagios";
my $email_template   = $opts->{e} || $default_templates->{$notificationtype};

# This is the part that is getting the notes
my $rs = Runtime::Schema->my_connect;
my $os = Opsview::Schema->my_connect;
my $note;

if ( $ENV{NAGIOS_SERVICEDESC} ) {
    my $o  = $rs->resultset("OpsviewHostObjects")->search(
        {
            'hostname' => { '=' => $ENV{NAGIOS_HOSTNAME} },
            'name2'    => { '=' => $ENV{NAGIOS_SERVICEDESC} }
        }
    )->first;

    if ( $o && $o->{_column_data}->{notes} == 1 ) {
        my $sn = $os->resultset("Serviceinfo")->search(
            {
                'id' => { '=' => $o->{_column_data}->{object_id} }
            }
        )->first;
        $note = $sn->{_column_data}->{information};
    }
}
else {
    my $o = $os->resultset("Hosts")->search(
        { 'name' => { '=' => $ENV{NAGIOS_HOSTNAME} } }
    )->first;
    if ( $o && $o->{_column_data}->{id} ) {
         my $hn = $os->resultset("Hostinfo")->search(
              { 'id' => { '=' => $o->{_column_data}->{id} } }
         )->first;
         $note = $hn->{_column_data}->{information};
    }
}
my $root = HTML::TreeBuilder->new_from_content($note);
my $formatter = HTML::FormatText->new();
$note = $formatter->format($root);

$ENV{NAGIOS_SERVICENOTES} = $note;

my $ok =
  Opsview::Utils::NotificationTemplate->process( $email_template, \$output,
    \$error );

if ( !$ok ) {
    print "Error: $error\n";
    die;
}

if ( $opts->{t} ) {
    print "TESTING OUTPUT\n";
    print $output;
    exit;
}

# Use first line as subject
my $subject;
($subject) = ( $output =~ /^(.+)$/m );

# Encode as base-64 and mark as utf8 to allow non-ascii chars in subject header
$subject = "=?utf-8?B?" . encode_base64( $subject, "" ) . "?=";

my $pid = open EMAIL, "|-", "/usr/bin/Mail", "-s", $subject, $email;

unless ( defined $pid ) {

    # Try alternative if /usr/bin/Mail is not present, an issue on Ubuntu18
    # TODO OP-45555 we might not need this if we have the correct dependencies for all OSes
    $pid = open EMAIL, "|-", "/usr/bin/mail", "-s", $subject, $email;
}

if ( defined $pid ) {
    print EMAIL $output;
}
else {
    die "Error: Could not send email using /usr/bin/Mail or /usr/bin/mail";
}
close EMAIL;

print "Sent email!\n";
exit;