#!/usr/bin/env perl

use strict;
use warnings;

use FindBin qw($Bin);
use Crypt::OpenSSL::CMS;

use Test::More tests => 6;

my $cms = Crypt::OpenSSL::CMS->new(
    cert     => "$Bin/certificate.cer",
    key      => "$Bin/private.key",
    key_pass => "qwerty",
);

my $pem  = _slurp_file("$Bin/signed.cms");
my $data = "This is signed message";

is($cms->verify($pem, Crypt::OpenSSL::CMS::CMS_NO_SIGNER_CERT_VERIFY), $data, 'Verify data signed by OpenSSL');

ok($pem = $cms->sign($data), 'Sign');

is($cms->verify($pem, Crypt::OpenSSL::CMS::CMS_NO_SIGNER_CERT_VERIFY), $data, 'Verify');

ok($pem = $cms->encrypt($data, "$Bin/certificate.cer"), 'Encrypt');

is($cms->decrypt($pem), $data, 'Decrypt');

ok($cms->dump_as_string($pem), 'Dump pem as string');


sub _slurp_file {
    local $/ = undef;
    open(my $fh, "<", $_[0]) or die "Couldn't open file: $!";
    my $string = <$fh>;
    close($fh);
    return $string;
}
