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

#include <ngx_mail.h>
#include "ngx_ssl_ct_module.h"

static char *ngx_mail_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_mail_module_t ngx_mail_ssl_ct_module_ctx = {
    NULL,                           /* protocol */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    &ngx_ssl_ct_create_srv_conf,    /* create server configuration */
    &ngx_mail_ssl_ct_merge_srv_conf /* merge server configuration */
};

static ngx_command_t ngx_mail_ssl_ct_commands[] = {
    {
        ngx_string("ssl_ct"),
        NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG,
        &ngx_conf_set_flag_slot,
        NGX_MAIL_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, enable),
        NULL
    },
    {
        ngx_string("ssl_ct_static_scts"),
        NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_array_slot,
        NGX_MAIL_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, sct_dirs),
        NULL
    },
    {
        ngx_string("ssl_ct_log"),
        NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_slot,
        NGX_MAIL_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, ctlog),
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_mail_ssl_ct_module = {
    NGX_MODULE_V1,
    &ngx_mail_ssl_ct_module_ctx, /* module context */
    ngx_mail_ssl_ct_commands,    /* module directives */
    NGX_MAIL_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_mail_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child) {
    ngx_mail_ssl_conf_t *ssl_conf = ngx_mail_conf_get_module_srv_conf(cf,
        ngx_mail_ssl_module);

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
