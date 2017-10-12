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
            lib     => 'crypto.1.0.0',
            symbol  => 'PEM_read_bio_CMS',
            libpath => ["/lib/x86_64-linux-gnu/", "/usr/local/opt/openssl/lib"]
        )
    );

    sub _last_error;

    my $wrapper = sub {
        my $func = shift;
        my $ret = $func->( @_ );
        _croak(_last_error) unless $ret;
        return $ret;
    };

    $ffi->type( 'opaque' => 'BIO' );
    $ffi->type( 'opaque' => 'X509' );
    $ffi->type( 'opaque' => 'PKEY' );
    $ffi->type( 'opaque' => 'CMS' );
    $ffi->type( 'opaque' => 'X509_STACK' );

    $ffi->attach( OPENSSL_add_all_algorithms_noconf => [] => 'void' );
    $ffi->attach( ERR_load_crypto_strings           => [] => 'void' );

    $ffi->attach( ERR_get_error      => [] => 'uint64' );
    $ffi->attach( ERR_error_string_n => [ 'uint64', 'opaque', 'size_t' ] => 'void' );

    $ffi->attach( BIO_s_mem       => []                                 => 'opaque', $wrapper );
    $ffi->attach( BIO_new         => ['opaque']                         => 'BIO', $wrapper );
    $ffi->attach( BIO_new_file    => [ 'string', 'string' ]             => 'BIO', $wrapper );
    $ffi->attach( BIO_new_mem_buf => [ 'string', 'int' ]                => 'BIO', $wrapper );
    $ffi->attach( BIO_ctrl        => [ 'BIO', 'int', 'int', 'opaque*' ] => 'long', $wrapper );
    $ffi->attach( BIO_free        => ['BIO']                            => 'void' );

    $ffi->attach( PEM_read_bio_CMS        => [ 'BIO', 'opaque', 'opaque', 'opaque' ] => 'CMS', $wrapper );
    $ffi->attach( PEM_read_bio_X509       => [ 'BIO', 'opaque', 'opaque', 'opaque' ] => 'X509', $wrapper );
    $ffi->attach( PEM_read_bio_PrivateKey => [ 'BIO', 'opaque', 'opaque', 'string' ] => 'PKEY', $wrapper );
    $ffi->attach( PEM_write_bio_CMS       => [ 'BIO', 'CMS',    'BIO',    'int' ]    => 'int', $wrapper );

    $ffi->attach( EVP_PKEY_free    => ['PKEY'] => 'void' );
    $ffi->attach( EVP_des_ede3_cbc => []       => 'opaque' );

    $ffi->attach( X509_free                    => ['X509'] => 'void' );
    $ffi->attach( X509_STORE_new               => [] => 'opaque', $wrapper );
    $ffi->attach( X509_STORE_add_cert          => [ 'opaque', 'X509' ] => 'opaque', $wrapper);
    $ffi->attach( X509_STORE_load_locations    => [ 'opaque', 'string', 'string'] => 'int', $wrapper);
    $ffi->attach( X509_STORE_set_default_paths => [ 'opaque' ] => 'int', $wrapper);
    $ffi->attach( X509_STORE_free              => [ 'opaque' ] => 'void' );

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
    return bless { map { $_ => $args{$_} } qw[ca_file ca_path cert key key_pass] }, $class;
}

sub verify {
    my ($self, %args) = @_;

    my ($bio, $cert, $certs, $store, $cms, $data);

    try {
        if ($args{cert}) {
            $bio = BIO_new_file($args{cert}, 'r');

            $cert = PEM_read_bio_X509($bio, undef, undef, undef);

            $certs = sk_new_null();
            sk_push($certs, $cert);
            $cert = undef;

            BIO_free($bio);
            $bio = undef;
        }

        $store = X509_STORE_new;

        my $ca_file = $args{ca_file} // ( ref($self) ? $self->{ca_file} : undef );
        my $ca_path = $args{ca_path} // ( ref($self) ? $self->{ca_path} : undef );

        if ($ca_file || $ca_path) {
            X509_STORE_load_locations($store, $ca_file, $ca_path);
        } else {
            X509_STORE_set_default_paths($store);
        }

        if ($args{string}) {
            $bio = BIO_new_mem_buf($args{string}, -1);
        } elsif ($args{file}) {
            $bio = BIO_new_file($args{file}, 'r');
        } else {
            die('string or file required for verify()');
        }

        $cms = PEM_read_bio_CMS($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;

        $bio = BIO_new(BIO_s_mem);

        CMS_verify($cms, $certs, $store, undef, $bio, $args{flags});

        my $buf;
        my $len = BIO_ctrl($bio, BIO_CTRL_INFO(), 0, \$buf);

        $data = buffer_to_scalar($buf, $len);
    } catch {
        _croak("Verify failed: $_");
    } finally {
        BIO_free($bio) if $bio;
        X509_free($cert) if $cert;
        sk_pop_free($certs, $ffi->find_symbol('X509_free')) if $certs;
        # FIXME
        X509_STORE_free($store) if $store;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $data;
}

sub sign {
    my ($self, %args) = @_;

    my($bio, $cert, $key, $cms, $pem);

    try {
        $bio = BIO_new_file($self->{cert}, 'r');
        $cert = PEM_read_bio_X509($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;

        $bio = BIO_new_file($self->{key}, 'r');
        $key = PEM_read_bio_PrivateKey($bio, undef, undef, $args{key_pass} // ( ref($self) ? $self->{key_pass} : undef ));
        BIO_free($bio); $bio = undef;

        if ($args{string}) {
            $bio = BIO_new_mem_buf($args{string}, -1);
        } elsif ($args{file}) {
            $bio = BIO_new_file($args{file}, 'r');
        } else {
            die('string or file required for sign()');
        }

        $cms = CMS_sign($cert, $key, undef, $bio, $args{flags});
        BIO_free($bio); $bio = undef;

        $bio = BIO_new(BIO_s_mem);

        PEM_write_bio_CMS($bio, $cms, undef, 0);

        my $buf;
        my $len = BIO_ctrl($bio, BIO_CTRL_INFO(), 0, \$buf);

        $pem = buffer_to_scalar($buf, $len);
    } catch {
        _croak("Sign failed: $_");
    } finally {
        BIO_free($bio) if $bio;
        X509_free($cert) if $cert;
        EVP_PKEY_free($key) if $key;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $pem;
}

sub encrypt {
    my ($self, %args) = @_;

    my $pem;

    my ($bio, $cert, $certs, $cms);

    try {
        $bio = BIO_new_file($args{recipient}, "r");
        $cert = PEM_read_bio_X509($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;

        my $certs = sk_new_null();
        sk_push($certs, $cert);
        $cert = undef;

        if ($args{string}) {
            $bio = BIO_new_mem_buf($args{string}, -1);
        } elsif ($args{file}) {
            $bio = BIO_new_file($args{file}, 'r');
        } else {
            die('string or file required for encrypt()');
        }

        $cms = CMS_encrypt($certs, $bio, EVP_des_ede3_cbc(), $args{flags});
        BIO_free($bio); $bio = undef;

        $bio = BIO_new(BIO_s_mem);

        PEM_write_bio_CMS($bio, $cms, undef, 0);

        my $buf;
        my $len = BIO_ctrl($bio, BIO_CTRL_INFO(), 0, \$buf);

        $pem = buffer_to_scalar($buf, $len);
    } catch {
        _croak("Encrypt failed: $_");
    } finally {
        BIO_free($bio) if $bio;
        X509_free($cert) if $cert;
        sk_pop_free($certs, $ffi->find_symbol('X509_free')) if $certs;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $pem;
}

sub decrypt {
    my ($self, %args) = @_;

    my ($bio, $cert,$key, $cms, $data);

    try {
        $bio = BIO_new_file($self->{cert}, "r");
        $cert = PEM_read_bio_X509($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;

        $bio = BIO_new_file($self->{key}, "r");
        $key = PEM_read_bio_PrivateKey($bio, undef, undef, $self->{key_pass});
        BIO_free($bio); $bio = undef;

        if ($args{string}) {
            $bio = BIO_new_mem_buf($args{string}, -1);
        } elsif ($args{file}) {
            $bio = BIO_new_file($args{file}, 'r');
        } else {
            die('string or file required for decrypt()');
        }

        $cms = PEM_read_bio_CMS($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;


        $bio = BIO_new(BIO_s_mem);

        CMS_decrypt($cms, $key, $cert, undef, $bio, $args{flags});

        my $buf;
        my $len = BIO_ctrl($bio, BIO_CTRL_INFO(), 0, \$buf);

        $data = buffer_to_scalar($buf, $len);
    } catch {
        _croak("Decrypt failed: $_");
    } finally {
        BIO_free($bio) if $bio;
        X509_free($cert) if $cert;
        EVP_PKEY_free($key) if $key;
        CMS_ContentInfo_free($cms) if $cms;
    };

    return $data;
}

sub dump {
    my ($self, %args) = @_;

    my $string;
    my ($bio, $cms);

    try {
        if ($args{string}) {
            $bio = BIO_new_mem_buf($args{string}, -1);
        } elsif ($args{file}) {
            $bio = BIO_new_file($args{file}, 'r');
        } else {
            die('string or file required for dump()');
        }

        $cms = PEM_read_bio_CMS($bio, undef, undef, undef);
        BIO_free($bio); $bio = undef;

        $bio = BIO_new(BIO_s_mem);

        CMS_ContentInfo_print_ctx($bio, $cms, 0, undef);

        my $buf;
        my $len = BIO_ctrl($bio, BIO_CTRL_INFO(), 0, \$buf);

        $string = buffer_to_scalar($buf, $len);
    } catch {
        _croak("Dump failed: $_");
    } finally {
        BIO_free($bio) if $bio;
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

sub _croak {
    local $Carp::CarpLevel = 1;
    croak(@_);
}


1;

__END__

=head1 NAME

Crypt::OpenSSL::CMS - L<FFI|FFI::Platypus> Perl bindings to OpenSSL L<Cryptographic Message Syntax (CMS)|https://tools.ietf.org/html/rfc5652> API (former PKCS7)

=head1 SYNOPSIS

    use Crypt::OpenSSL::CMS;
    my $cms = Crypt::OpenSSL::CMS->new(
        ca_file  => "certificate.cer",
        cert     => "certificate.cer",
        key      => "private.key",
        key_pass => "password",
    );

    $message = $cms->verify(file => 'signed.pem');
    $pem = $cms->sign(string => $message);

=head1 CONSTRUCTOR

=head2 new( %attributes )

Create a new instance.

=over

=item ca_file

Path to trusted certificates file

=item ca_path

Path to trusted certificates directory

=item cert

Path to personal certificate file

=item key

Path to personal private key file

=item key_pass

Password for the private key

=back

=head1 METHODS

=head2 verify

    $cms->verify( file => 'signed.pem' );
    # OR
    $cms->verify( string => $signed_data );

    # with additional parameters
    $cms->verify( file => 'signed.pem', flags => Crypt::OpenSSL::CMS::CMS_NO_SIGNER_CERT_VERIFY );
    $cms->verify( file => 'signed.pem', cert => 'cert.cer' );
    $cms->verify( file => 'signed.pem', ca_file => 'cert.cer' );

Verify CMS content in pem format and return signed data on success.

=head2 sign

    $cms->sign( string => $data );
    $cms->sign( file => 'message.txt', flags => Crypt::OpenSSL::CMS::CMS_NOCERTS );

Sign data and return CMS content in pem format.

=head2 encrypt

    $cms->encrypt( string => $data, recipient => 'john.cer', flags => $flags );

Encrypt data and return CMS content in pem format.

=head2 decrypt

    $cms->decrypt( string => $data, flags => $flags )

Decrypt CMS content in pem format and return decrypted data.

=head2 dump

    $cms->dump( string => $data );

Return text dump. For example:

    CMS_ContentInfo:
      contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
      d.envelopedData:
        version: <ABSENT>
        originatorInfo: <ABSENT>
        recipientInfos:
          d.ktri:
            version: <ABSENT>
            d.issuerAndSerialNumber:
              issuer: CN=PKCS#7 example
              serialNumber: 14646190812765378694
            keyEncryptionAlgorithm:
              algorithm: rsaEncryption (1.2.840.113549.1.1.1)
              parameter: NULL
            encryptedKey:
              0000 - ae a3 c8 d5 8f a3 27 19-aa 9c 09 ec 85 c9 1c   ......'........
              000f - 2b a4 1b dd 2c b9 fe 1e-b3 bd 18 8b 67 2a 7b   +...,.......g*{
              001e - a6 20 36 5c 6b 3a 93 81-65 43 e3 4d f1 9f 97   . 6\k:..eC.M...
              002d - b1 ff d3 b1 27 66 b4 b1-85 2e e6 3f b3 f7 78   ....'f.....?..x
              003c - 69 3d 5e 58 fa c9 05 21-f6 72 47 b9 36 af a0   i=^X...!.rG.6..
              004b - ee eb 6d d7 4f 02 99 24-a6 9c 68 5c d2 da cd   ..m.O..$..h\...
              005a - 40 53 e9 a0 01 60 c8 d5-54 76 f1 bd 21 f3 e5   @S...`..Tv..!..
              0069 - b7 69 9e ee a3 de 8f ff-33 ed 79 01 a9 a1 70   .i......3.y...p
              0078 - 2a c7 e8 9b 94 29 83 2a-98 26 f3 d3 8b 65 21   *....).*.&...e!
              0087 - b1 fb 34 a6 68 fb 97 be-f2 1f f0 fd 2f 35 4d   ..4.h......./5M
              0096 - 6b 0d 32 19 05 8d 3f 2c-2e 44 ff 95 ae 05 23   k.2...?,.D....#
              00a5 - 87 57 ff c0 93 ac f6 36-0a e5 1d 60 08 24 ad   .W.....6...`.$.
              00b4 - 23 af 0f b8 31 f9 e5 38-61 d2 e6 65 9c 75 e6   #...1..8a..e.u.
              00c3 - 46 ac a3 04 c7 d1 e4 22-48 54 94 e5 24 71 49   F......"HT..$qI
              00d2 - 4f 7c db fc a9 bd ea 07-64 5f 49 4c 7d 3b 96   O|......d_IL};.
              00e1 - 56 61 0b 8d 2e e1 de c1-42 59 de 01 1f cd 8c   Va......BY.....
              00f0 - 42 2f 01 f6 32 ef e6 14-09 9b ee 80 22 be 81   B/..2......."..
              00ff - 88                                             .
        encryptedContentInfo:
          contentType: pkcs7-data (1.2.840.113549.1.7.1)
          contentEncryptionAlgorithm:
            algorithm: des-ede3-cbc (1.2.840.113549.3.7)
            parameter: OCTET STRING:
              0000 - 9c c9 65 53 99 bd af 9f-                       ..eS....
          encryptedContent:
            0000 - ba 18 3b 1c 90 a1 10 37-89 69 72 db d6 ad 56   ..;....7.ir...V
            000f - 52 eb 39 58 d6 12 3f fd-9a                     R.9X..?..
        unprotectedAttrs:
          <EMPTY>

=head1 FLAGS

B<Flags constants are not exported, so you should prefix them with Crypt::OpenSSL::CMS::>

For additional info, please look at man page L<cms(1)|https://linux.die.net/man/1/cms>

=over

=item CMS_TEXT

=item CMS_NOCERTS

=item CMS_NO_CONTENT_VERIFY

=item CMS_NO_ATTR_VERIFY

=item CMS_NOSIGS

=item CMS_NOINTERN

=item CMS_NO_SIGNER_CERT_VERIFY

=item CMS_NOVERIFY

=item CMS_DETACHED

=item CMS_BINARY

=item CMS_NOATTR

=item CMS_NOSMIMECAP

=item CMS_NOOLDMIMETYPE

=item CMS_CRLFEOL

=item CMS_STREAM

=item CMS_NOCRL

=item CMS_PARTIAL

=item CMS_REUSE_DIGEST

=item CMS_USE_KEYID

=item CMS_DEBUG_DECRYPT

=item CMS_KEY_PARAM

=back

=head1 AUTHOR

Alexander Batyrshin, C<0x62ash@gmail.com>.
