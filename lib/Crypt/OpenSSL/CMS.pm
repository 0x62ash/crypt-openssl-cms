package Crypt::OpenSSL::CMS;

use strict;
use warnings;

use Carp;
use FFI::CheckLib;
use FFI::Platypus;
use FFI::Platypus::Buffer;
use FFI::Platypus::Memory qw( malloc );
use Try::Tiny;

our $VERSION = '0.01';

my $ffi;

BEGIN {
    $ffi = FFI::Platypus->new;

    $ffi->lib(
        find_lib_or_die(
            lib     => 'crypto',
            symbol  => 'PEM_read_bio_CMS',
            libpath => ["/usr/local/", "/usr/local/opt/openssl/lib"]
        )
    );

    sub _last_error;

    my $wrapper = sub {
        my $func = shift;
        my $ret = $func->( @_ );
        local $Carp::CarpLevel = 1;
        croak(_last_error) unless $ret;
        #die(_last_error) unless $ret;
        return $ret;
    };

    $ffi->type( 'opaque' => 'BIO' );
    $ffi->type( 'opaque' => 'X509' );
    $ffi->type( 'opaque' => 'PKEY' );
    $ffi->type( 'opaque' => 'CMS' );
    $ffi->type( 'opaque' => 'X509_STACK' );

    $ffi->attach( OPENSSL_add_all_algorithms_noconf => [] => 'void' );
    $ffi->attach( ERR_load_crypto_strings           => [] => 'void' );

    $ffi->attach( ERR_get_error => [] => 'uint64' );
    $ffi->attach( ERR_error_string_n => [ 'uint64', 'opaque', 'size_t' ] => 'void' );

    $ffi->attach( BIO_s_mem => []         => 'opaque', $wrapper );
    $ffi->attach( BIO_new   => ['opaque'] => 'BIO', $wrapper );
    $ffi->attach( BIO_new_file    => [ 'string', 'string' ] => 'BIO', $wrapper );
    $ffi->attach( BIO_new_mem_buf => [ 'string', 'int' ]    => 'BIO', $wrapper );
    $ffi->attach( BIO_ctrl => [ 'BIO', 'int', 'int', 'opaque*' ] => 'long', $wrapper );
    $ffi->attach( BIO_free => ['BIO'] => 'void' );

    $ffi->attach( PEM_read_bio_CMS        => [ 'BIO', 'opaque', 'opaque', 'opaque' ] => 'CMS', $wrapper );
    $ffi->attach( PEM_read_bio_X509       => [ 'BIO', 'opaque', 'opaque', 'opaque' ] => 'X509', $wrapper );
    $ffi->attach( PEM_read_bio_PrivateKey => [ 'BIO', 'opaque', 'opaque', 'string' ] => 'PKEY', $wrapper );
    $ffi->attach( PEM_write_bio_CMS       => [ 'BIO', 'CMS',    'BIO',    'int' ]    => 'int', $wrapper );

    $ffi->attach( EVP_PKEY_free    => ['PKEY'] => 'void' );
    $ffi->attach( EVP_des_ede3_cbc => []       => 'opaque' );

    $ffi->attach( X509_STORE_new => []       => 'opaque', $wrapper );
    $ffi->attach( X509_free      => ['X509'] => 'void' );

    $ffi->attach( sk_new_null => [] => 'X509_STACK', $wrapper );
    $ffi->attach( sk_push     => [ 'X509_STACK', 'X509' ]   => 'int', $wrapper );
    $ffi->attach( sk_pop_free => [ 'X509_STACK', 'opaque' ] => 'void' );

    $ffi->attach( CMS_verify  => [ 'CMS', 'X509_STACK', 'opaque', 'opaque', 'BIO', 'int' ] => 'int', $wrapper );
    $ffi->attach( CMS_sign    => [ 'X509', 'PKEY', 'X509_STACK', 'BIO', 'int' ] => 'CMS', $wrapper );
    $ffi->attach( CMS_encrypt => [ 'X509_STACK', 'BIO', 'opaque', 'int' ] => 'CMS', $wrapper );
    $ffi->attach( CMS_decrypt => [ 'CMS', 'PKEY', 'X509', 'BIO', 'BIO', 'int' ] => 'int', $wrapper );
    $ffi->attach( CMS_ContentInfo_print_ctx => [ 'BIO', 'CMS', 'int', 'opaque' ] => 'int', $wrapper );

    $ffi->attach( CMS_ContentInfo_free => ['CMS'] => 'void' );

    OPENSSL_add_all_algorithms_noconf();
    ERR_load_crypto_strings();
}

use namespace::clean;

use constant BIO_CTRL_INFO => 3;

use constant CMS_TEXT                  => 0x1;
use constant CMS_NOCERTS               => 0x2;
use constant CMS_NO_CONTENT_VERIFY     => 0x4;
use constant CMS_NO_ATTR_VERIFY        => 0x8;
use constant CMS_NOSIGS                => (CMS_NO_CONTENT_VERIFY|CMS_NO_ATTR_VERIFY);
use constant CMS_NOINTERN              => 0x10;
use constant CMS_NO_SIGNER_CERT_VERIFY => 0x20;
use constant CMS_NOVERIFY              => 0x20;
use constant CMS_DETACHED              => 0x40;
use constant CMS_BINARY                => 0x80;
use constant CMS_NOATTR                => 0x100;
use constant CMS_NOSMIMECAP            => 0x200;
use constant CMS_NOOLDMIMETYPE         => 0x400;
use constant CMS_CRLFEOL               => 0x800;
use constant CMS_STREAM                => 0x1000;
use constant CMS_NOCRL                 => 0x2000;
use constant CMS_PARTIAL               => 0x4000;
use constant CMS_REUSE_DIGEST          => 0x8000;
use constant CMS_USE_KEYID             => 0x10000;
use constant CMS_DEBUG_DECRYPT         => 0x20000;
use constant CMS_KEY_PARAM             => 0x40000;


sub new {
    my ($class, %args) = @_;
    return bless { map { $_ => $args{$_} } qw[cert key key_pass] }, $class;
}

sub verify {
    my ($self, $pem, $flags) = @_;

    my $data;

    my ($bio_in, $bio_out, $cms);

    try {
        $bio_in = BIO_new_mem_buf($pem, -1);

        $cms = PEM_read_bio_CMS($bio_in, undef, undef, undef);

        $bio_out = BIO_new(BIO_s_mem);

        CMS_verify($cms, undef, undef, undef, $bio_out, $flags);

        my $buf;
        my $len = BIO_ctrl($bio_out, BIO_CTRL_INFO(), 0, \$buf);

        $data = buffer_to_scalar($buf, $len);
    } catch {
        die("Verify failed: $_");
    } finally {
        BIO_free($bio_in) if $bio_in;
        BIO_free($bio_out) if $bio_out;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $data;
}

sub sign {
    my ($self, $data, $flags) = @_;

    my $pem;

    my($bio_cert, $cert, $bio_key, $key, $bio_in, $cms, $bio_out);

    try {
        my $bio_cert = BIO_new_file($self->{cert}, "r");

        my $cert = PEM_read_bio_X509($bio_cert, undef, undef, undef);

        my $bio_key = BIO_new_file($self->{key}, "r");

        my $key = PEM_read_bio_PrivateKey($bio_key, undef, undef, $self->{key_pass});

        my $bio_in = BIO_new_mem_buf($data, -1);

        my $cms = CMS_sign($cert, $key, undef, $bio_in, $flags);

        my $bio_out = BIO_new(BIO_s_mem);

        PEM_write_bio_CMS($bio_out, $cms, undef, 0);

        my $buf;
        my $len = BIO_ctrl($bio_out, BIO_CTRL_INFO(), 0, \$buf);

        $pem = buffer_to_scalar($buf, $len);
    } catch {
        die("Sign failed: $_");
    } finally {
        BIO_free($bio_cert) if $bio_cert;
        BIO_free($bio_key) if $bio_key;
        BIO_free($bio_in) if $bio_in;
        X509_free($cert) if $cert;
        EVP_PKEY_free($key) if $key;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $pem;
}

sub encrypt {
    my ($self, $data, $recipient, $flags) = @_;

    my $pem;

    my ($bio_cert, $cert, $recips, $cms, $bio_in, $bio_out);

    try {
        my $bio_cert = BIO_new_file($self->{cert}, "r");

        my $cert = PEM_read_bio_X509($bio_cert, undef, undef, undef);

        my $recips = sk_new_null();

        sk_push($recips, $cert);

        $cert = undef;

        my $bio_in = BIO_new_mem_buf($data, -1);

        my $cms = CMS_encrypt($recips, $bio_in, EVP_des_ede3_cbc(), $flags);

        my $bio_out = BIO_new(BIO_s_mem);

        PEM_write_bio_CMS($bio_out, $cms, undef, 0);

        my $buf;
        my $len = BIO_ctrl($bio_out, BIO_CTRL_INFO(), 0, \$buf);

        $pem = buffer_to_scalar($buf, $len);
    } catch {
        die("Encrypt failed: $_");
    } finally {
        BIO_free($bio_cert) if $bio_in;
        X509_free($cert) if $cert;
        sk_pop_free($recips, $ffi->find_symbol('X509_free')) if $recips;
        CMS_ContentInfo_free($cms) if $cms;
        BIO_free($bio_in) if $bio_in;
        BIO_free($bio_out) if $bio_out;
    };

    return $pem;
}

sub decrypt {
    my ($self, $pem, $flags) = @_;

    my $data;

    my ($bio_cert, $cert, $bio_key, $key, $bio_in, $bio_out, $cms);

    try {
        my $bio_cert = BIO_new_file($self->{cert}, "r");

        my $cert = PEM_read_bio_X509($bio_cert, undef, undef, undef);

        my $bio_key = BIO_new_file($self->{key}, "r");

        my $key = PEM_read_bio_PrivateKey($bio_key, undef, undef, $self->{key_pass});

        my $bio_in = BIO_new_mem_buf($pem, -1);

        my $cms = PEM_read_bio_CMS($bio_in, undef, undef, undef);

        my $bio_out = BIO_new(BIO_s_mem);

        CMS_decrypt($cms, $key, $cert, undef, $bio_out, $flags);

        my $buf;
        my $len = BIO_ctrl($bio_out, BIO_CTRL_INFO(), 0, \$buf);

        $data = buffer_to_scalar($buf, $len);
    } catch {
        die("Decrypt failed: $_");
    } finally {
        BIO_free($bio_in) if $bio_in;
        BIO_free($bio_out) if $bio_out;
        BIO_free($bio_cert) if $bio_cert;
        BIO_free($bio_key) if $bio_key;
        X509_free($cert) if $cert;
        EVP_PKEY_free($key) if $key;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $data;
}

sub dump_as_string {
    my ($self, $pem) = @_;

    my $string;
    my ($bio_in, $cms, $bio_out);

    try {
        $bio_in = BIO_new_mem_buf($pem, -1);
        $cms = PEM_read_bio_CMS($bio_in, undef, undef, undef);
        $bio_out = BIO_new(BIO_s_mem);

        CMS_ContentInfo_print_ctx($bio_out, $cms, 0, undef);

        my $buf;
        my $len = BIO_ctrl($bio_out, BIO_CTRL_INFO(), 0, \$buf);

        $string = buffer_to_scalar($buf, $len);
    } catch {
        die("Dump failed: $_");
    } finally {
        BIO_free($bio_in) if $bio_in;
        BIO_free($bio_out) if $bio_out;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $string;
}

sub _last_error {
    my $buf_size = 256;
    my $buf = malloc($buf_size);
    ERR_error_string_n(ERR_get_error(), $buf, $buf_size);
    my $string = (split("\0", buffer_to_scalar($buf, $buf_size)))[0];
    return $string;
}


1;

__END__

=head1 NAME

Crypt::OpenSSL::CMS - Perl bindings to OpenSSL CMS API (former PKCS7)

=head1 SYNOPSIS

    use Crypt::OpenSSL::CMS;
    my $cms = Crypt::OpenSSL::CMS->new(
        cert     => "certificate.cer",
        key      => "private.key",
        key_pass => "password",
    );

    $signed_data = $cms->verify($pem);
    $pem = $cms->sign($data_to_sign);
    ...

=head1 METHODS

=head2 new( %attributes )

Create a new instance.

=over

=item cert

Path to certificate file

=item key

Path to private key file

=item key_pass

Password for the private key

=back

=head2 virify( $pem, $flags )

Verify CMS content in pem format and return signed data on success

=head2 sign( $data, $flags )

Sign data and return CMS content in pem format

=head2 encode( $data, $flags )

Encode data and return CMS content in pem format

=head2 decode( $pem, $flags )

Decode CMS content in pem format and return decoded data

=head1 AUTHOR

Alexander Batyrshin, C<0x62ash@gmail.com>.
