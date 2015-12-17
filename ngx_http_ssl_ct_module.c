/*
 * Copyright (c) 2015 Graham Edgecombe <gpe@grahamedgecombe.com>
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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_SSL
#error ngx_http_ssl_ct_module requires the ngx_http_ssl_module to be enabled
#else

#define NGX_HTTP_SSL_CT_EXT 18 /* from RFC 6962 */
#define NGX_HTTP_SSL_CT_EXT_MAX_LEN 0xFFFF
#define ngx_strrchr(s1, c) strrchr((const char *) s1, (int) c)

typedef struct
{
    ngx_flag_t enable;
    ngx_str_t  sct;
} ngx_http_ssl_ct_srv_conf_t;

typedef struct
{
    u_char buf[NGX_HTTP_SSL_CT_EXT_MAX_LEN];
    size_t len;
} ngx_http_ssl_ct_ext;

static void *ngx_http_ssl_ct_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
#ifndef OPENSSL_IS_BORINGSSL
static int ngx_http_ssl_ct_ext_cb(SSL *s, unsigned int ext_type,
    const unsigned char **out, size_t *outlen, int *al, void *add_arg);
#endif
static ngx_http_ssl_ct_ext *ngx_http_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_http_ssl_ct_ext *sct_list);
static ngx_http_ssl_ct_ext *ngx_http_ssl_ct_read_static_scts(ngx_conf_t *cf,
    ngx_str_t *path);

static ngx_http_module_t ngx_http_ssl_ct_module_ctx = {
    NULL,                             /* preconfiguration */
    NULL,                             /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    &ngx_http_ssl_ct_create_srv_conf, /* create server configuration */
    &ngx_http_ssl_ct_merge_srv_conf,  /* merge server configuration */

    NULL,                             /* create location configuration */
    NULL                              /* merge location configuration */
};

static ngx_command_t ngx_http_ssl_ct_commands[] = {
    {
        ngx_string("ssl_ct"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        &ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_ct_srv_conf_t, enable),
        NULL
    },
    {
        ngx_string("ssl_ct_static_scts"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        &ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_ct_srv_conf_t, sct),
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

static void *ngx_http_ssl_ct_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_ct_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    /*
     * set by ngx_pcalloc():
     *
     *     conf->sct = { 0, NULL };
     */

    return conf;
}

static char *ngx_http_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    /* merge config */
    ngx_http_ssl_ct_srv_conf_t *prev = parent;
    ngx_http_ssl_ct_srv_conf_t *conf = child;

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

    /* get ngx_http_ssl_module configuration and check if SSL is enabled */
    ngx_http_ssl_srv_conf_t *ssl_conf = ngx_http_conf_get_module_srv_conf(cf,
        ngx_http_ssl_module);

    if (!ssl_conf->ssl.ctx)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "\"ssl_ct\" can only be enabled if ssl is enabled");
        return NGX_CONF_ERROR;
    }

    /* read .sct files */
    ngx_http_ssl_ct_ext *sct_list = ngx_http_ssl_ct_read_static_scts(cf,
        &conf->sct);
    if (!sct_list)
    {
        /* ngx_http_ct_read_static_scts calls ngx_log_error */
        return NGX_CONF_ERROR;
    }

    /* add OpenSSL TLS extension */
#ifndef OPENSSL_IS_BORINGSSL
    if (SSL_CTX_add_server_custom_ext(ssl_conf->ssl.ctx, NGX_HTTP_SSL_CT_EXT,
        &ngx_http_ssl_ct_ext_cb, NULL, sct_list, NULL, NULL) == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_add_server_custom_ext failed");
        ngx_pfree(cf->pool, sct_list);
        return NGX_CONF_ERROR;
    }
#else
    if (SSL_CTX_set_signed_cert_timestamp_list(ssl_conf->ssl.ctx, sct_list->buf, sct_list->len) == 0)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_set_signed_cert_timestamp_list failed");
        ngx_pfree(cf->pool, sct_list);
        return NGX_CONF_ERROR;
    }
#endif

    return NGX_CONF_OK;
}

#ifndef OPENSSL_IS_BORINGSSL
static int ngx_http_ssl_ct_ext_cb(SSL *s, unsigned int ext_type,
    const unsigned char **out, size_t *outlen, int *al, void *add_arg)
{
    ngx_http_ssl_ct_ext *sct_list = add_arg;
    *out    = sct_list->buf;
    *outlen = sct_list->len;
    return 1;
}
#endif

static ngx_http_ssl_ct_ext *ngx_http_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_http_ssl_ct_ext *sct_list)
{
    /* reserve two bytes for the length */
    size_t len_pos = sct_list->len;
    sct_list->len += 2;
    if (sct_list->len > NGX_HTTP_SSL_CT_EXT_MAX_LEN)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "sct_list structure exceeds maximum length");
        return NULL;
    }

    /* join dir and file name */
    size_t path_len = dir->len + file_len + 2;
    u_char *path = ngx_pcalloc(cf->pool, path_len);
    if (path == NULL)
    {
        return NULL;
    }

    u_char *path_end = ngx_cpystrn(path, dir->data, dir->len + 1);
    *path_end++ = '/';
    ngx_cpystrn(path_end, file, file_len + 1);

    /* open file */
    ngx_fd_t fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_FILE_ERROR)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_open_file_n " \"%s\" failed", path);
        ngx_pfree(cf->pool, path);
        return NULL;
    }

    /* get file size */
    ngx_file_info_t stat;
    if (ngx_fd_info(fd, &stat) == NGX_FILE_ERROR)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_fd_info_n " \"%s\" failed", path);

        if (ngx_close_file(fd) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                ngx_close_file_n " \"%s\" failed", path);
        }

        ngx_pfree(cf->pool, path);
        return NULL;
    }

    size_t sct_len = ngx_file_size(&stat);

    /* reserve sct_len bytes for the SCT */
    size_t sct_pos = sct_list->len;
    sct_list->len += sct_len;
    if (sct_list->len > NGX_HTTP_SSL_CT_EXT_MAX_LEN)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "sct_list structure exceeds maximum length");

        if (ngx_close_file(fd) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                ngx_close_file_n " \"%s\" failed", path);
        }

        ngx_pfree(cf->pool, path);
        return NULL;
    }

    /* read the SCT from disk */
    size_t to_read = sct_len;
    while (to_read > 0)
    {
        ssize_t n = ngx_read_fd(fd, sct_list->buf + sct_pos, to_read);
        if (n == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                ngx_read_fd_n " \"%s\" failed", path);

            if (ngx_close_file(fd) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                    ngx_close_file_n " \"%s\" failed", path);
            }

            ngx_pfree(cf->pool, path);
            return NULL;
        }

        to_read -= n;
        sct_pos += n;
    }

    /* close file */
    if (ngx_close_file(fd) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_close_file_n " \"%s\" failed", path);
    }

    ngx_pfree(cf->pool, path);

    /* fill in the length bytes and return */
    sct_list->buf[len_pos] = sct_len >> 8;
    sct_list->buf[len_pos + 1] = sct_len;
    return sct_list;
}

static ngx_http_ssl_ct_ext *ngx_http_ssl_ct_read_static_scts(ngx_conf_t *cf,
    ngx_str_t *path)
{
    /* resolve relative paths */
    if (ngx_conf_full_name(cf->cycle, path, 1) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            "ngx_conf_full_name \"%V\" failed");
        return NULL;
    }

    /* allocate sct_list structure */
    ngx_http_ssl_ct_ext *sct_list = ngx_pcalloc(cf->pool, sizeof(*sct_list));
    if (!sct_list)
    {
        return NULL;
    }

    /* reserve the first two bytes for the length */
    sct_list->len += 2;

    /* open directory */
    ngx_dir_t dir;
    if (ngx_open_dir(path, &dir) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_open_dir_n " \"%V\" failed", path);
        ngx_pfree(cf->pool, sct_list);
        return NULL;
    }

    /* iterate through all files */
    for (;;)
    {
        ngx_set_errno(NGX_ENOMOREFILES);

        if (ngx_read_dir(&dir) != NGX_OK)
        {
            ngx_err_t err = ngx_errno;

            if (err == NGX_ENOMOREFILES)
            {
                break;
            }
            else
            {
                ngx_log_error(NGX_LOG_EMERG, cf->log, err,
                    ngx_read_dir_n " \"%V\" failed", path);
                ngx_pfree(cf->pool, sct_list);
                return NULL;
            }
        }

        /* skip dotfiles */
        size_t file_len = ngx_de_namelen(&dir);
        u_char *file = ngx_de_name(&dir);
        if (file[0] == '.')
        {
            continue;
        }

        /* skip files unless the extension is .sct */
        u_char *file_ext = (u_char *) ngx_strrchr(file, '.');
        if (!file_ext || ngx_strcmp(file_ext, ".sct"))
        {
            continue;
        }

        /* add the .sct file to the sct_list */
        if (!ngx_http_ssl_ct_read_static_sct(cf, path, file, file_len,
            sct_list))
        {
            /* ngx_http_ssl_ct_read_static_sct calls ngx_log_error */
            ngx_pfree(cf->pool, sct_list);
            return NULL;
        }
    }

    /* close directory */
    if (ngx_close_dir(&dir) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_close_dir_n " \"%V\" failed", path);
        ngx_pfree(cf->pool, sct_list);
        return NULL;
    }

    /* fill in the length bytes and return */
    size_t sct_list_len = sct_list->len - 2;
    sct_list->buf[0] = sct_list_len >> 8;
    sct_list->buf[1] = sct_list_len;
    return sct_list;
}

#endif
