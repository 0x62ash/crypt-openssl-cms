# NAME

[![Build Status](https://travis-ci.org/0x62ash/crypt-openssl-cms.svg?branch=master)](https://travis-ci.org/0x62ash/crypt-openssl-cms)

Crypt::OpenSSL::CMS - [FFI](https://metacpan.org/pod/FFI::Platypus) Perl bindings to OpenSSL [Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652) API (former PKCS7)

# SYNOPSIS

    use Crypt::OpenSSL::CMS;
    my $cms = Crypt::OpenSSL::CMS->new(
        ca_file  => "certificate.cer",
        cert     => "certificate.cer",
        key      => "private.key",
        key_pass => "password",
    );

    $message = $cms->verify(file => 'signed.pem');
    $pem = $cms->sign(string => $message);

# CONSTRUCTOR

## new( %attributes )

Create a new instance.

- ca\_file

    Path to trusted certificates file

- ca\_path

    Path to trusted certificates directory

- cert

    Path to personal certificate file

- key

    Path to personal private key file

- key\_pass

    Password for the private key

# METHODS

## verify

    $cms->verify( file => 'signed.pem' );
    # OR
    $cms->verify( string => $signed_data );

    # with additional parameters
    $cms->verify( file => 'signed.pem', flags => Crypt::OpenSSL::CMS::CMS_NO_SIGNER_CERT_VERIFY );
    $cms->verify( file => 'signed.pem', cert => 'cert.cer' );
    $cms->verify( file => 'signed.pem', ca_file => 'cert.cer' );

Verify CMS content in pem format and return signed data on success.

## sign

    $cms->sign( string => $data );
    $cms->sign( file => 'message.txt', flags => Crypt::OpenSSL::CMS::CMS_NOCERTS );

Sign data and return CMS content in pem format.

## encrypt

    $cms->encrypt( string => $data, recipient => 'john.cer', flags => $flags );

Encrypt data and return CMS content in pem format.

## decrypt

    $cms->decrypt( string => $data, flags => $flags )

Decrypt CMS content in pem format and return decrypted data.

## dump

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

# FLAGS

**Flags constants are not exported, so you should prefix them with Crypt::OpenSSL::CMS::**

For additional info, please look at man page [cms(1)](https://linux.die.net/man/1/cms)

- CMS\_TEXT
- CMS\_NOCERTS
- CMS\_NO\_CONTENT\_VERIFY
- CMS\_NO\_ATTR\_VERIFY
- CMS\_NOSIGS
- CMS\_NOINTERN
- CMS\_NO\_SIGNER\_CERT\_VERIFY
- CMS\_NOVERIFY
- CMS\_DETACHED
- CMS\_BINARY
- CMS\_NOATTR
- CMS\_NOSMIMECAP
- CMS\_NOOLDMIMETYPE
- CMS\_CRLFEOL
- CMS\_STREAM
- CMS\_NOCRL
- CMS\_PARTIAL
- CMS\_REUSE\_DIGEST
- CMS\_USE\_KEYID
- CMS\_DEBUG\_DECRYPT
- CMS\_KEY\_PARAM

# AUTHOR

Alexander Batyrshin, `0x62ash@gmail.com`.
