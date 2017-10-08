#!/usr/bin/env perl

use strict;
use warnings;

use FindBin qw($Bin);
use Crypt::OpenSSL::CMS;

use Test::More tests => 6;

my $cms = Crypt::OpenSSL::CMS->new(
    ca_file  => "$Bin/certificate.cer",
    cert     => "$Bin/certificate.cer",
    key      => "$Bin/private.key",
    key_pass => "qwerty",
);

my $pem;
my $data = "This is signed message";

is($cms->verify(file => "$Bin/signed.cms"), $data, 'Verify data signed by OpenSSL');

ok($pem = $cms->sign(string => $data), 'Sign');

is($cms->verify(string => $pem), $data, 'Verify');

ok($pem = $cms->encrypt(string => $data, recipient => "$Bin/certificate.cer"), 'Encrypt');

is($cms->decrypt(string => $pem), $data, 'Decrypt');

ok($cms->dump(string => $pem), 'Dump pem as string');


done_testing;
