/*
 * Copyright (c) 2015-2017 Graham Edgecombe <gpe@grahamedgecombe.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _NGX_SSL_CT_H_INCLUDED_
#define _NGX_SSL_CT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_SSL_CT_EXT 18 /* from RFC 6962 */
#define NGX_SSL_CT_EXT_MAX_LEN 0xFFFF
#define ngx_strrchr(s1, c) strrchr((const char *) s1, (int) c)

typedef struct {
    ngx_flag_t   enable;
    ngx_array_t *sct_dirs;
} ngx_ssl_ct_srv_conf_t;

typedef struct {
    u_char buf[NGX_SSL_CT_EXT_MAX_LEN];
    size_t len;
} ngx_ssl_ct_ext;

ngx_int_t ngx_ssl_ct_init(ngx_log_t *log);
#ifndef OPENSSL_IS_BORINGSSL
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
int ngx_ssl_ct_ext_cb(SSL *s, unsigned int ext_type, unsigned int context,
    const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx,
    int *al, void *add_arg);
#  else
int ngx_ssl_ct_ext_cb(SSL *s, unsigned int ext_type, const unsigned char **out,
    size_t *outlen, int *al, void *add_arg);
#  endif
#endif
ngx_ssl_ct_ext *ngx_ssl_ct_read_static_scts(ngx_conf_t *cf, ngx_str_t *path);
void *ngx_ssl_ct_create_srv_conf(ngx_conf_t *cf);
char *ngx_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child,
    SSL_CTX *ssl_ctx, ngx_array_t *certificates);

#endif
