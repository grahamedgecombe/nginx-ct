/*
 * Copyright (c) 2015-2016 Graham Edgecombe <gpe@grahamedgecombe.com>
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
        &ngx_conf_set_str_slot,
        NGX_MAIL_SRV_CONF_OFFSET,
        offsetof(ngx_ssl_ct_srv_conf_t, sct),
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
    void *child)
{
    /* merge config */
    ngx_ssl_ct_srv_conf_t *prev = parent;
    ngx_ssl_ct_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->sct, prev->sct, "");

    /* validate config */
    if (conf->enable)
    {
        if (conf->sct.len == 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "no \"ssl_ct_static_scts\" is defined for the \"ssl_ct\""
                "directive");
            return NGX_CONF_ERROR;
        }
    }
    else
    {
        return NGX_CONF_OK;
    }

    /* get ngx_mail_ssl_module configuration and check if SSL is enabled */
    ngx_mail_ssl_conf_t *ssl_conf = ngx_mail_conf_get_module_srv_conf(cf,
        ngx_mail_ssl_module);

    if (!ssl_conf->ssl.ctx)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "\"ssl_ct\" can only be enabled if ssl is enabled");
        return NGX_CONF_ERROR;
    }

    /* read .sct files */
    ngx_ssl_ct_ext *sct_list = ngx_ssl_ct_read_static_scts(cf, &conf->sct);
    if (!sct_list)
    {
        /* ngx_ssl_ct_read_static_scts calls ngx_log_error */
        return NGX_CONF_ERROR;
    }

    /* add OpenSSL TLS extension */
#ifndef OPENSSL_IS_BORINGSSL
    if (SSL_CTX_add_server_custom_ext(ssl_conf->ssl.ctx, NGX_SSL_CT_EXT,
        &ngx_ssl_ct_ext_cb, NULL, sct_list, NULL, NULL) == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_add_server_custom_ext failed");
        ngx_pfree(cf->pool, sct_list);
        return NGX_CONF_ERROR;
    }
#else
    if (SSL_CTX_set_signed_cert_timestamp_list(ssl_conf->ssl.ctx, sct_list->buf,
        sct_list->len) == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_set_signed_cert_timestamp_list failed");
        ngx_pfree(cf->pool, sct_list);
        return NGX_CONF_ERROR;
    }
#endif

    return NGX_CONF_OK;
}
