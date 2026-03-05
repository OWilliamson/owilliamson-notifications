#!/usr/bin/perl -w
#
# notify_by_snmp_v3.pl - Notification script for ITRS OP5 Monitor
#                     that sends notifications as SNMP traps.
#
# Author: Mathias Sundman <ms@op5.se>
#
# Version: 2.0 2007-02-21
#
# Copyright(C) 2007 OP5 AB
# All rights reserved.
#
# History:
# 
# v3.0 2024-07-17
#   Rewrite to support SNMPv3 using Net:SNMP
#
# v2.0 2007-02-21
#   Complete rewrite to send all objects specified in the Nagios MIB.
#
# v1.0 2007-02-20
#   Initial release
#
#

use strict;
use POSIX;
use Net::SNMP;
use SNMP_util "0.54";
use Getopt::Long;

sub print_usage ();
sub is_hostname ;
sub parse_args ();
sub logit ;
  
$ENV{'PATH'}='';
$ENV{'BASH_ENV'}='';
$ENV{'ENV'}='';

my $PROGNAME = "notify_by_snmp_v3.pl";
my $logfile = "/tmp/notify_by_snmp_v3.log";
  
# defaults
my $community = "public";
my $version = 3;
my $port = 162;
my $enterpriseOID = ".1.3.6.1.4.1.20006.1"; 	# NAGIOS-NOTIFY-MIB::nagiosNotify
my $generalID="6"; 				# enterprice Specific
my $specificID="1";
my $debug=0;
my $authproto = 'sha';
my $privproto = 'aes';
my $testoid = $enterpriseOID . '.' . 1 . "." . "nHostname";

# variables
my %val;
my $type;
my ($username, $authpasswd, $privpasswd, $hostname, $oid, $typeoid, $objtype, $string, $testtrap, @vars);

parse_args();

# Import MIBS
if (snmpMIB_to_OID("/usr/share/snmp/mibs/NAGIOS-ROOT-MIB.txt") < 1) {
    logit "/usr/share/snmp/mibs/NAGIOS-ROOT-MIB.txt not found\n";
	exit(1);
}
if (snmpMIB_to_OID("/usr/share/snmp/mibs/NAGIOS-NOTIFY-MIB.txt") < 1) {
    logit "/usr/share/snmp/mibs/NAGIOS-NOTIFY-MIB.txt not found\n";
	exit(1);
}

# Type Switches

if($val{"NOTIFICATIONTYPE"} eq "PROBLEM"){ $val{"NOTIFICATIONTYPE"}=0}
if($val{"NOTIFICATIONTYPE"} eq "RECOVERY"){ $val{"NOTIFICATIONTYPE"}=1}
if($val{"NOTIFICATIONTYPE"} eq "ACKNOWLEDGEMENT"){ $val{"NOTIFICATIONTYPE"}=2}
if($val{"NOTIFICATIONTYPE"} eq "FLAPPINGSTART"){ $val{"NOTIFICATIONTYPE"}=3}
if($val{"NOTIFICATIONTYPE"} eq "FLAPPINGSTOP"){ $val{"NOTIFICATIONTYPE"}=4}

if($val{"NOTIFICATIONTYPE"} eq "OK"){ $val{"NOTIFICATIONTYPE"}=0}
if($val{"NOTIFICATIONTYPE"} eq "WARNING"){ $val{"NOTIFICATIONTYPE"}=1}
if($val{"NOTIFICATIONTYPE"} eq "CRITICAL"){ $val{"NOTIFICATIONTYPE"}=2}
if($val{"NOTIFICATIONTYPE"} eq "UNKNOWN"){ $val{"NOTIFICATIONTYPE"}=3}

if ( $type eq "nHostNotify" || $type eq "nHostEvent" ) {
    if($val{"HOSTSTATETYPE"} eq "UP"){ $val{"HOSTSTATETYPE"}=0};
    if($val{"HOSTSTATETYPE"} eq "DOWN"){ $val{"HOSTSTATETYPE"}=1};
    if($val{"HOSTSTATETYPE"} eq "UNREACHABLE"){ $val{"HOSTSTATETYPE"}=2};
}

# Check required arguments based on SNMP version
if ($version eq '3') {
    if (!$username || !$authpasswd || !$privpasswd || !$hostname ) {
        print_usage();
        die "Missing required arguments for SNMP v3. ";
    }
} elsif ($version eq '1' || $version eq '2c' || $version eq '2') {
    if (!$community || !$hostname ) {
        print_usage();
        die "Missing required arguments for SNMP v1/2c. ";
    }
} else {
    die "Unsupported SNMP version. Use 1, 2c, or 3.\n";
    print_usage();
}

# Function to send SNMP trap

sub send_snmp_trap() {

# Create SNMP session

    my ($session, $error);
    if ($version eq '3') {
        ($session, $error) = Net::SNMP->session(
                            -hostname      => $hostname,
                            -port          => $port,
                            -version       => $version,
                            -username      => $username,    # v3
                            -authpassword  => $authpasswd,  # v3
                            -authprotocol  => $authproto,   # v3
                            -privpassword  => $privpasswd,  # v3
                            -privprotocol  => $privproto,   # v3
                         );
    }
    else {
        ($session, $error) = Net::SNMP->session(
                            -hostname      => $hostname,
                            -port          => $port,
                            -version       => $version,
                            -community     => $community,
                         );
    }
    
# Check for session creation error

    if (!defined $session) {
        die "ERROR: $error\n";
    }
    
# Set trap data
    
    @vars = qw();
    
    if (defined $testtrap) {
            print "Sending $testtrap to $hostname $port with oid $testoid\n"; 
            push (@vars, $testoid, OCTET_STRING, $testtrap);
    }
    elsif ($type eq "nHostEvent") {            ##### nHostEvent #####
            $typeoid = ".5";
    
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostname", OCTET_STRING, $val{"HOSTNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateID", INTEGER, $val{"HOSTSTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateType", INTEGER, $val{"HOSTSTATETYPE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostAttempt", INTEGER32, $val{"HOSTATTEMPT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostDurationSec", INTEGER32, $val{"HOSTDURATIONSEC"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostGroupName", OCTET_STRING, $val{"HOSTGROUPNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostLastCheck", INTEGER, $val{"LASTHOSTCHECK"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostLastChange", INTEGER, $val{"LASTHOSTSTATECHANGE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostOutput", OCTET_STRING, $val{"HOSTOUTPUT"});
    }
    elsif ($type eq "nHostNotify") {        ##### nHostNotify #####
            $typeoid = ".6";
    
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostNotifyType", INTEGER, $val{"NOTIFICATIONTYPE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostNotifyNum", INTEGER32, $val{"NOTIFICATIONNUMBER"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostAckAuthor", OCTET_STRING, $val{"HOSTACKAUTHOR"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostAckComment", OCTET_STRING, $val{"HOSTACKCOMMENT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostname", OCTET_STRING, $val{"HOSTNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateID", INTEGER, $val{"HOSTSTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateType", INTEGER, $val{"HOSTSTATETYPE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostAttempt", INTEGER32, $val{"HOSTATTEMPT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostDurationSec", INTEGER32, $val{"HOSTDURATIONSEC"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostGroupName", OCTET_STRING, $val{"HOSTGROUPNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostLastCheck", INTEGER, $val{"LASTHOSTCHECK"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostLastChange", INTEGER, $val{"LASTHOSTSTATECHANGE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostOutput", OCTET_STRING, $val{"HOSTOUTPUT"});
    }
    
    elsif ($type eq "nSvcEvent") {          ##### nSvcEvent #####
            $typeoid = ".7";
    
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostname", OCTET_STRING, $val{"HOSTNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateID", INTEGER, $val{"HOSTSTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcDesc", OCTET_STRING, $val{"SERVICEDESCRIPTION"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcID", INTEGER, $val{"SERVICESTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcAttempt", INTEGER32, $val{"SERVICEATTEMPT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceDurationSec", INTEGER32, $val{"SERVICEDURATIONSEC"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceGroupName", OCTET_STRING, $val{"SERVICEGROUPNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceLastCheck", INTEGER, $val{"LASTSERVICECHECK"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceLastChange", INTEGER, $val{"LASTSERVICESTATECHANGE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceOutput", OCTET_STRING, $val{"SERVICEOUTPUT"});
    }
    
    elsif ($type eq "nSvcNotify") {         ##### nSvcNotify #####
            $typeoid = ".8";
    
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostNotifyType", INTEGER, $val{"NOTIFICATIONTYPE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostNotifyNum", INTEGER32, $val{"NOTIFICATIONNUMBER"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcAckAuthor", OCTET_STRING, $val{"SERVICEACKAUTHOR"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcAckComment", OCTET_STRING, $val{"SERVICEACKCOMMENT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostname", OCTET_STRING, $val{"HOSTNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nHostStateID", INTEGER, $val{"HOSTSTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcDesc", OCTET_STRING, $val{"SERVICEDESCRIPTION"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcID", INTEGER, $val{"SERVICESTATEID"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nSvcAttempt", INTEGER32, $val{"SERVICEATTEMPT"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceDurationSec", INTEGER32, $val{"SERVICEDURATIONSEC"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceGroupName", OCTET_STRING, $val{"SERVICEGROUPNAME"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceLastCheck", INTEGER, $val{"LASTSERVICECHECK"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceLastChange", INTEGER, $val{"LASTSERVICESTATECHANGE"});
            push (@vars, $enterpriseOID . '.' . $typeoid . "nServiceOutput", OCTET_STRING, $val{"SERVICEOUTPUT"});
    }
    else {
            logit "Unknown notification type!\n"; # This should not happend!
            print "Unknown notification type!\n"; # This should not happend!
            exit(1);
    }
    
# Send trap
    
    my $result;
    
    if ($version eq '3') {
        $result  = $session->snmpv3_trap(
                -varbindlist      => \@vars,
        );
    }
    else {
        $result  = $session->trap(
                -varbindlist      => \@vars,
        );
    }
    
# Check the trap sent
    
    if (!defined $result) {
        print "ERROR: ", $session->error, "\n";
    }
    else {
        print "SNMPv3 Trap sent successfully.\n";
    }
    
# Close session
    $session->close();

}

sub print_usage () {
        print "Usage: $PROGNAME -h <host> -t <notification-typ> [-C community] variables...

  -h, --hostname=HOST1             Name or IP address of host to send SNMP trap to
  -P, --port=port                  Defaults to 162
  -C, --community=COMMUNITY        SNMP community string (default: public)
  -v, --version=Version            SNMP version (1|2c|3)
  -u, --username=Username          Username for SNMPv3 user
  -a, --authProtocol=authProtocol  SNMPv3 authentication protocol (md5|sha)
  -A, --authPassword=authPassword  SNMPv3 authentication password
  -x, --privProtocol=privProtocol  SNMPv3 privacy protocol (aes128|3des)
  -X, --privPassword=privPassword  SNMPv3 privacy password
  -t, --type=notifitcation-type    Notification Type (nHostEvent | nHostNotify | nSvcEvent | nSvcNotify)
  -T, --testtrap=trapvalue         Generate test trap with specivied text string as the value
  -o, --testoid=oid                OID to send test trap to
	
  Freeform variables should be specified as 'VARIABLE=VALUE'.
";
	exit(1);

}

sub parse_args() {

	my ($k, $v, $i);

	# parse arguments
	if($#ARGV < 2) {
	        print_usage();
	}
	for($i=0; $i<=$#ARGV; $i++) {
	        if($ARGV[$i] =~ /^-h|^--hostname/) {
	                $hostname = $ARGV[++$i];
	        }
	        elsif($ARGV[$i] =~ /^-v|^--version/) {
	                $version = $ARGV[++$i];
	        }
                elsif($ARGV[$i] =~ /^-C|^--community/) {
                        $community = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-a|^--authProtocol/) {
                        $authproto = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-A|^--authPassword/) {
                        $authpasswd = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-x|^--privProtocol/) {
                        $privproto = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-X|^--privPassword/) {
                        $privpasswd = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-u|^--username/) {
                        $username = $ARGV[++$i];
                }
	        elsif($ARGV[$i] =~ /^-t|^--type/) {
	                $type = $ARGV[++$i];
	        }
	        elsif($ARGV[$i] =~ /^-d|^--debug/) {
	                $debug = 1;
	        }
                elsif($ARGV[$i] =~ /^-T|^--testtrap/) {
                        $testtrap = $ARGV[++$i];
                }
                elsif($ARGV[$i] =~ /^-o|^--testoid/) {
                        $testoid = $ARGV[++$i];
                }
	        elsif($ARGV[$i] =~ /^([^=]*)=(.*)$/) {
	                # this is a free form variable, so register it
	                $k = $1;
	                $v = $2;
	                $val{$k} = $v;
	        }
	        else {
	                print "Unknown option: " . $ARGV[$i] . "\n\n";
	                logit "Unknown option: " . $ARGV[$i] . "\n\n";
	                print_usage();
	        }
	}

        if (defined $testtrap) {
            unless (defined $val{"HOSTNAME"}) {
                $val{"HOSTNAME"} = $hostname;
            }
            unless (defined $val{"NOTIFICATIONTYPE"}) {
                $val{"NOTIFICATIONTYPE"} = "PROBLEM";
            }
            unless (defined $val{"SERVICEDESCRIPTION"}) {
                $val{"SERVICEDESCRIPTION"} = "Test Service";
            }
        }
	
	unless (defined $hostname) {
	        print "\nNo target hostname specified.\n";
	        logit "No target hostname specified.\n";
	        exit(1);
	}
	if (! is_hostname($hostname)){
	        print "$hostname is not a valid hostname.\n";
	        logit "$hostname is not a valid hostname.\n";
	        exit(1);
	}
	
	unless (defined $type) {
	        logit "No notification-type specified.\n";
	        print "\nNo notification-type specified.\n";
	        exit(1);
	}

	if ($type eq "nHostEvent") {
		unless (defined $val{"HOSTNAME"}) {
	        	logit "No HOSTNAME variable specified.\n";
	        	print "\nNo HOSTNAME variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"HOSTSTATEID"}) {
			$val{"HOSTSTATEID"} = 0;
		}
		unless (defined $val{"HOSTSTATETYPE"}) {
			$val{"HOSTSTATETYPE"} = 0;
		}
		unless (defined $val{"HOSTATTEMPT"}) {
			$val{"HOSTATTEMPT"} = 0;
		}
		unless (defined $val{"HOSTDURATIONSEC"}) {
			$val{"HOSTDURATIONSEC"} = 0;
		}
		unless (defined $val{"HOSTGROUPNAME"}) {
			$val{"HOSTGROUPNAME"} = "";
		}
		unless (defined $val{"LASTHOSTCHECK"}) {
			$val{"LASTHOSTCHECK"} = 0;
		}
		unless (defined $val{"LASTHOSTSTATECHANGE"}) {
			$val{"LASTHOSTSTATECHANGE"} = 0;
		}
		unless (defined $val{"HOSTOUTPUT"}) {
			$val{"HOSTOUTPUT"} = "<No output from host>";
		}
	}
	elsif ($type eq "nHostNotify") {
		unless (defined $val{"NOTIFICATIONTYPE"}) {
	        	logit "No NOTIFICATIONTYPE variable specified.\n";
	        	print "\nNo NOTIFICATIONTYPE variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"NOTIFICATIONNUMBER"}) {
			$val{"NOTIFICATIONNUMBER"} = 0;
		}
		unless (defined $val{"HOSTACKAUTHOR"}) {
			$val{"HOSTACKAUTHOR"} = "";
		}
		unless (defined $val{"HOSTACKCOMMENT"}) {
			$val{"HOSTACKCOMMENT"} = "";
		}
		unless (defined $val{"HOSTNAME"}) {
	        	logit "No HOSTNAME variable specified.\n";
	        	print "\nNo HOSTNAME variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"HOSTSTATEID"}) {
			$val{"HOSTSTATEID"} = 0;
		}
		unless (defined $val{"HOSTSTATETYPE"}) {
			$val{"HOSTSTATETYPE"} = 0;
		}
		unless (defined $val{"HOSTATTEMPT"}) {
			$val{"HOSTATTEMPT"} = 0;
		}
		unless (defined $val{"HOSTDURATIONSEC"}) {
			$val{"HOSTDURATIONSEC"} = 0;
		}
		unless (defined $val{"HOSTGROUPNAME"}) {
			$val{"HOSTGROUPNAME"} = "";
		}
		unless (defined $val{"LASTHOSTCHECK"}) {
			$val{"LASTHOSTCHECK"} = 0;
		}
		unless (defined $val{"LASTHOSTSTATECHANGE"}) {
			$val{"LASTHOSTSTATECHANGE"} = 0;
		}
		unless (defined $val{"HOSTOUTPUT"}) {
			$val{"HOSTOUTPUT"} = "<No output from host>";
		}
	}
	elsif ($type eq "nSvcEvent") {
		unless (defined $val{"HOSTNAME"}) {
	        	logit "No HOSTNAME variable specified.\n";
	        	print "\nNo HOSTNAME variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"HOSTSTATEID"}) {
			$val{"HOSTSTATEID"} = 0;
		}
		unless (defined $val{"SERVICEDESCRIPTION"}) {
	        	logit "No SERVICEDESCRIPTION variable specified.\n";
	        	print "\nNo SERVICEDESCRIPTION variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"SERVICESTATEID"}) {
			$val{"SERVICESTATEID"} = 0;
		}
		unless (defined $val{"SERVICEATTEMPT"}) {
			$val{"SERVICEATTEMPT"} = 0;
		}
		unless (defined $val{"SERVICEDURATIONSEC"}) {
			$val{"SERVICEDURATIONSEC"} = 0;
		}
		unless (defined $val{"SERVICEGROUPNAME"}) {
			$val{"SERVICEGROUPNAME"} = "";
		}
		unless (defined $val{"LASTSERVICECHECK"}) {
			$val{"LASTSERVICECHECK"} = 0;
		}
		unless (defined $val{"LASTSERVICESTATECHANGE"}) {
			$val{"LASTSERVICESTATECHANGE"} = 0;
		}
		unless (defined $val{"SERVICEOUTPUT"}) {
			$val{"SERVICEOUTPUT"} = "<No output from service>";
		}
	}
	elsif ($type eq "nSvcNotify") {
		unless (defined $val{"NOTIFICATIONTYPE"}) {
	        	logit "No NOTIFICATIONTYPE variable specified.\n";
	        	print "\nNo NOTIFICATIONTYPE variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"NOTIFICATIONNUMBER"}) {
			$val{"NOTIFICATIONNUMBER"} = 0;
		}
		unless (defined $val{"SERVICEACKAUTHOR"}) {
			$val{"SERVICEACKAUTHOR"} = "";
		}
		unless (defined $val{"SERVICEACKCOMMENT"}) {
			$val{"SERVICEACKCOMMENT"} = "";
		}
		unless (defined $val{"HOSTNAME"}) {
	        	logit "No HOSTNAME variable specified.\n";
	        	print "\nNo HOSTNAME variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"HOSTSTATEID"}) {
			$val{"HOSTSTATEID"} = 0;
		}
		unless (defined $val{"SERVICEDESCRIPTION"}) {
	        	logit "No SERVICEDESCRIPTION variable specified.\n";
	        	print "\nNo SERVICEDESCRIPTION variable specified.\n";
		        exit(1);
		}
		unless (defined $val{"SERVICESTATEID"}) {
			$val{"SERVICESTATEID"} = 0;
		}
		unless (defined $val{"SERVICEATTEMPT"}) {
			$val{"SERVICEATTEMPT"} = 0;
		}
		unless (defined $val{"SERVICEDURATIONSEC"}) {
			$val{"SERVICEDURATIONSEC"} = 0;
		}
		unless (defined $val{"SERVICEGROUPNAME"}) {
			$val{"SERVICEGROUPNAME"} = "";
		}
		unless (defined $val{"LASTSERVICECHECK"}) {
			$val{"LASTSERVICECHECK"} = 0;
		}
		unless (defined $val{"LASTSERVICESTATECHANGE"}) {
			$val{"LASTSERVICESTATECHANGE"} = 0;
		}
		unless (defined $val{"SERVICEOUTPUT"}) {
			$val{"SERVICEOUTPUT"} = "<No output from service>";
		}
	}
	else {
		logit "Unknown notification-type.\n\n";
		print "Unknown notification-type.\n\n";
		print_usage();
		exit(1);
	}
}

sub is_hostname 
{
        my $host1 = shift;
        if ($host1 && $host1 =~ m/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z][-a-zA-Z0-9]+(\.[a-zA-Z][-a-zA-Z0-9]+)*)$/) {
                return 1;
        }else{
                return 0;
        }
}


sub logit {
    if($debug != 0) {
	my $msg = shift;
	my $now = localtime time;
	my $file = $logfile;
	open FILE, ">>$file" or die "unable to open $file $!";
	print FILE "$now - $msg";
    }
}

send_snmp_trap();
