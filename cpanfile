requires 'namespace::clean';
requires 'Carp';
requires 'FFI::Platypus';
requires 'Try::Tiny';

on 'test' => sub {
    requires 'Test::More', '0.98';
};

