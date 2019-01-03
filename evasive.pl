#!/usr/bin/perl

use strict;
use Time::HiRes;
use Sys::Syslog;

my %uri_ip = ();
my %blocked = ();
my %white = ();

my $PAGE_INTERVAL = $ARGV[0] ? $ARGV[0] : 30;
my $PAGE_COUNT = $ARGV[1] ? $ARGV[1] : 5;
my $BLOCKING_PERIOD = 60;

my $time = time();
my $debug = 0;
openlog('evasive', 0, 'LOG_LOCAL0');

while (my $str = <STDIN>) {
    if (time() - $time > 300) {
        print "Cleanup started ".Time::HiRes::time()."\n" if $debug;
        foreach (keys %uri_ip) {
            if (Time::HiRes::time() - $uri_ip{$_}->[0] > $PAGE_INTERVAL*2) {
                delete $uri_ip{$_};
            }
        }
        print "Cleanup finished ".Time::HiRes::time()."\n" if $debug;
        $time = time();
    }
    my ($host, $ip, $request) = $str =~ /^([\w.-]+?) ([\d.]+) - - .+\] "([A-Z]+ .+?)"/;
    next unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    next if $request =~ m!\.(jpg|gif|jpeg|ico|png) HTTP/1\.[01]!i;
    if ($white{$ip}) {next;}
    if (exists $blocked{$ip}) {
        if (Time::HiRes::time() - $blocked{$ip} <= $BLOCKING_PERIOD) {
            print "block $ip continue\n" if $debug;
        } else {
            print "unblock $ip\n" if $debug;
            delete $blocked{$ip};
        }
        next;
    }
    my $key = "$host\t$request\t$ip";
    if (exists $uri_ip{$key}) {
        my $data = $uri_ip{$key};
        print "$ip ".Time::HiRes::time()." - $data->[0] = ".(Time::HiRes::time() - $data->[0])." $data->[1]\n" if $debug;
        if (Time::HiRes::time() - $data->[0] <= $PAGE_INTERVAL and $data->[1] > $PAGE_COUNT) {
            $blocked{$ip} = Time::HiRes::time();
            print "block $ip new\n" if $debug;
            system('/sbin/iptables -A INPUT -s '.$ip.' -p tcp --dport 80:80 -j DROP');
            syslog('LOG_NOTICE', "$ip blocked ($key, $data->[1] req > $PAGE_COUNT, $PAGE_INTERVAL sec >= ".(Time::HiRes::time() - $data->[0]).")");
            delete $uri_ip{$key};
            next;
        } elsif (Time::HiRes::time() - $data->[0] > $PAGE_INTERVAL) {
            $data->[0] = Time::HiRes::time();
            $data->[1] = 0;
        }
        $data->[1]++;
    } else {
        $uri_ip{$key} = [Time::HiRes::time(), 0];
        print "new ip $ip\n" if $debug;
    }
}

