# UNRELEASED

* Add TLS 1.3 support.
* Build CT modules if the mail/stream modules are dynamically linked.
* Add module name macros.

# 1.3.2 (30 November 2016)

* Don't send invalid zero-length SCT extensions.

# 1.3.1 (20 September 2016)

* Use exported functions to get the negotiated SSL certificate.

# 1.3.0 (10 July 2016)

* Fix compatibility with nginx 1.11.2 when the stream module is enabled.
* Add support for multiple certificates when using nginx 1.11.0 or above.

# 1.2.0 (14 February 2016)

* Add dynamic module support.

# 1.1.0 (5 February 2016)

* Add BoringSSL support.
* Add support for the mail and stream modules.

# 1.0.0 (11 November 2015)

* Initial stable release.
