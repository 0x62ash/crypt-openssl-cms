# NAME

Crypt::OpenSSL::CMS - Perl bindings to OpenSSL CMS API (former PKCS7)

# SYNOPSIS

    use Crypt::OpenSSL::CMS;
    my $cms = Crypt::OpenSSL::CMS->new(
        cert     => "certificate.cer",
        key      => "private.key",
        key_pass => "password",
    );

    $signed_data = $cms->verify($pem);
    $pem = $cms->sign($data_to_sign);
    ...

# METHODS

## new( %attributes )

Create a new instance.

- cert

    Path to certificate file

- key

    Path to private key file

- key\_pass

    Password for the private key

## virify( $pem, $flags )

Verify CMS content in pem format and return signed data on success

## sign( $data, $flags )

Sign data and return CMS content in pem format

## encode( $data, $flags )

Encode data and return CMS content in pem format

## decode( $pem, $flags )

Decode CMS content in pem format and return decoded data

# AUTHOR

Alexander Batyrshin, `0x62ash@gmail.com`.
