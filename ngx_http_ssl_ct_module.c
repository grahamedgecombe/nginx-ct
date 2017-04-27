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

#include <ngx_http.h>
#include "ngx_ssl_ct_module.h"

static char *ngx_http_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_http_module_t ngx_http_ssl_ct_module_ctx = {
    NULL,                            /* preconfiguration */
    NULL,                            /* postconfiguration */

    NULL,                            /* create main configuration */
    NULL,                            /* init main configuration */

    &ngx_ssl_ct_create_srv_conf,     /* create server configuration */
    &ngx_http_ssl_ct_merge_srv_conf, /* merge server configuration */

    NULL,                            /* create location configuration */
    NULL                             /* merge location configuration */
};

static ngx_command_t ngx_http_ssl_ct_commands[] = {
    {
        ngx_string("ssl_ct"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        &ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, enable),
        NULL
    },
    {
        ngx_string("ssl_ct_static_scts"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_array_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, sct_dirs),
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_http_ssl_ct_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_ct_module_ctx, /* module context */
    ngx_http_ssl_ct_commands,    /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child) {
    ngx_http_ssl_srv_conf_t *ssl_conf = ngx_http_conf_get_module_srv_conf(cf,
        ngx_http_ssl_module);

    ngx_array_t *certificates;

#if nginx_version >= 1011000
    certificates = ssl_conf->certificates;
#else
    certificates = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));

    ngx_str_t *certificate = ngx_array_push(certificates);
    *certificate = ssl_conf->certificate;
#endif

    return ngx_ssl_ct_merge_srv_conf(cf, parent, child, ssl_conf->ssl.ctx,
        certificates);
}
