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

#include "ngx_ssl_ct_module.h"

static ngx_ssl_ct_ext *ngx_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_ssl_ct_ext *sct_list);

static ngx_core_module_t ngx_ssl_ct_module_ctx = {
    ngx_string("ssl_ct"),

    NULL, /* create main configuration */
    NULL  /* init main configuration */
};

ngx_module_t ngx_ssl_ct_module = {
    NGX_MODULE_V1,
    &ngx_ssl_ct_module_ctx, /* module context */
    NULL,                   /* module directives */
    NGX_CORE_MODULE,        /* module type */
    NULL,                   /* init master */
    NULL,                   /* init module */
    NULL,                   /* init process */
    NULL,                   /* init thread */
    NULL,                   /* exit thread */
    NULL,                   /* exit process */
    NULL,                   /* exit master */
    NGX_MODULE_V1_PADDING
};

void *ngx_ssl_ct_create_srv_conf(ngx_conf_t *cf)
{
    ngx_ssl_ct_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
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

#ifndef OPENSSL_IS_BORINGSSL
int ngx_ssl_ct_ext_cb(SSL *s, unsigned int ext_type, const unsigned char **out,
    size_t *outlen, int *al, void *add_arg)
{
    ngx_ssl_ct_ext *sct_list = add_arg;
    *out    = sct_list->buf;
    *outlen = sct_list->len;
    return 1;
}
#endif

static ngx_ssl_ct_ext *ngx_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_ssl_ct_ext *sct_list)
{
    /* reserve two bytes for the length */
    size_t len_pos = sct_list->len;
    sct_list->len += 2;
    if (sct_list->len > NGX_SSL_CT_EXT_MAX_LEN)
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
    if (sct_list->len > NGX_SSL_CT_EXT_MAX_LEN)
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

ngx_ssl_ct_ext *ngx_ssl_ct_read_static_scts(ngx_conf_t *cf, ngx_str_t *path)
{
    /* resolve relative paths */
    if (ngx_conf_full_name(cf->cycle, path, 1) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            "ngx_conf_full_name \"%V\" failed");
        return NULL;
    }

    /* allocate sct_list structure */
    ngx_ssl_ct_ext *sct_list = ngx_pcalloc(cf->pool, sizeof(*sct_list));
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
        if (!ngx_ssl_ct_read_static_sct(cf, path, file, file_len, sct_list))
        {
            /* ngx_ssl_ct_read_static_sct calls ngx_log_error */
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
