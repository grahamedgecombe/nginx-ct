nginx Certificate Transparency module
=====================================

Introduction
------------

This module adds support for the TLS `signed_certificate_timestamp` extension to
nginx, which is one of the mechanisms supported by Google's
[Certificate Transparency][ct] project to deliver Signed Certificate Timestamps
to TLS clients.

Building
--------

Add `--add-module=/path/to/nginx-ct` to the nginx `./configure` invocation.
nginx must be compiled with OpenSSL support or it will fail to build. OpenSSL
1.0.2 or above is required, as the module makes use of the new
`SSL_CTX_add_server_custom_ext` function.

LibreSSL is not supported as it doesn't have support for the
`SSL_CTX_add_server_custom_ext` function.

BoringSSL is supported with the macro OPENSSL_IS_BORINGSSL :
Add `--with-cc-opt='-D_OPENSSL_IS_BORINGSSL` to the nginx `./configure`
invocation.

Configuration
-------------

Add the following directives, which are valid in both `http` and `server`
blocks, to your configuration file:

    ssl_ct on;
    ssl_ct_static_scts /path/to/sct/dir;

The module will read all `*.sct` files in the given directory, which are
expected to be encoded in binary (see the definition of
`SignedCertificateTimestamp` struct in [section 3.2 of RFC 6962][rfc]). This is
the same format used by Apache's [mod\_ssl\_ct][apache] module.

[ct-submit][ct-submit] can be used to submit certificates to log servers and
encode the `SignedCertificateTimestamp` struct in the appropriate format for use
with this module.

License
-------

This project is available under the terms of the ISC license, which is similar
to the 2-clause BSD license. See the `LICENSE` file for the copyright
information and licensing terms.

[ct]: http://www.certificate-transparency.org/
[rfc]: https://tools.ietf.org/html/rfc6962#section-3.2
[apache]: https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html
[ct-submit]: https://github.com/grahamedgecombe/ct-submit
