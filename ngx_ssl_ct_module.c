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

#include "ngx_ssl_ct_module.h"

static int ngx_ssl_ct_sct_list_index;

static void *ngx_ssl_ct_create_conf(ngx_cycle_t *cycle);
static ngx_ssl_ct_ext *ngx_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_ssl_ct_ext *sct_list);

static ngx_core_module_t ngx_ssl_ct_module_ctx = {
    ngx_string("ssl_ct"),

    &ngx_ssl_ct_create_conf, /* create main configuration */
    NULL                     /* init main configuration */
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

static void *ngx_ssl_ct_create_conf(ngx_cycle_t *cycle) {
    ngx_ssl_ct_sct_list_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
        NULL);

    if (ngx_ssl_ct_sct_list_index == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
            "X509_get_ex_new_index failed");
        return NULL;
    }

    return ngx_palloc(cycle->pool, 0);
}

void *ngx_ssl_ct_create_srv_conf(ngx_conf_t *cf) {
    ngx_ssl_ct_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->sct_dirs = NGX_CONF_UNSET_PTR;

    return conf;
}

char *ngx_ssl_ct_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child,
    SSL_CTX *ssl_ctx, ngx_array_t *certificates) {
    /* merge config */
    ngx_ssl_ct_srv_conf_t *prev = parent;
    ngx_ssl_ct_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->sct_dirs, prev->sct_dirs, NULL);

    /* validate config */
    if (conf->enable) {
        if (!conf->sct_dirs) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "no \"ssl_ct_static_scts\" is defined for the \"ssl_ct\""
                "directive");
            return NGX_CONF_ERROR;
        }
    } else {
        return NGX_CONF_OK;
    }

    /* check if SSL is enabled */
    if (!ssl_ctx) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "\"ssl_ct\" can only be enabled if ssl is enabled");
        return NGX_CONF_ERROR;
    }

    /* check we have one SCT dir for each certificate */
    ngx_uint_t sct_dir_count = conf->sct_dirs->nelts;
    if (sct_dir_count != certificates->nelts) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "there must be exactly one \"ssl_ct_static_scts\" directive for "
            "each \"ssl_certificate\" directive");
        return NGX_CONF_ERROR;
    }

    /* loop through all the certs/SCT dirs */
    ngx_str_t *sct_dirs = conf->sct_dirs->elts;
    X509 *cert = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_certificate_index);

    ngx_uint_t i;
    for (i = 0; i < sct_dir_count; i++) {
        /* the certificate linked list is stored in reverse order */
        ngx_str_t *sct_dir = &sct_dirs[sct_dir_count - i - 1];

        /* read the .sct files for this cert */
        ngx_ssl_ct_ext *sct_list = ngx_ssl_ct_read_static_scts(cf, sct_dir);
        if (!sct_list) {
            /* ngx_ssl_ct_read_static_scts calls ngx_log_error */
            return NGX_CONF_ERROR;
        }

        if (sct_list->len == 0) {
            ngx_pfree(cf->pool, sct_list);
            goto next;
        }

#ifndef OPENSSL_IS_BORINGSSL
        /* associate the sct_list with the cert */
        X509_set_ex_data(cert, ngx_ssl_ct_sct_list_index, sct_list);
#else
        if (SSL_CTX_set_signed_cert_timestamp_list(ssl_ctx, sct_list->buf,
            sct_list->len) == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "SSL_CTX_set_signed_cert_timestamp_list failed");
            ngx_pfree(cf->pool, sct_list);
            return NGX_CONF_ERROR;
        }

        if (conf->sct_dirs->nelts > 1) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                "BoringSSL does not support using SCTs with multiple "
                "certificates, the last non-empty \"ssl_ct_static_scts\" "
                "directory will be used for all certificates");
        }

        break;
#endif

next:
#if nginx_version >= 1011000
        cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index);
#else
        break;
#endif
    }

#ifndef OPENSSL_IS_BORINGSSL
    /* add OpenSSL TLS extension */
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
    int context = SSL_EXT_CLIENT_HELLO
                | SSL_EXT_TLS1_2_SERVER_HELLO
                | SSL_EXT_TLS1_3_CERTIFICATE;
    if (SSL_CTX_add_custom_ext(ssl_ctx, NGX_SSL_CT_EXT, context,
        &ngx_ssl_ct_ext_cb, NULL, NULL, NULL, NULL) == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_add_custom_ext failed");
        return NGX_CONF_ERROR;
    }
#  else
    if (SSL_CTX_add_server_custom_ext(ssl_ctx, NGX_SSL_CT_EXT,
        &ngx_ssl_ct_ext_cb, NULL, NULL, NULL, NULL) == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "SSL_CTX_add_server_custom_ext failed");
        return NGX_CONF_ERROR;
    }
#  endif
#endif

    return NGX_CONF_OK;
}

#ifndef OPENSSL_IS_BORINGSSL
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
int ngx_ssl_ct_ext_cb(SSL *s, unsigned int ext_type, unsigned int context,
    const unsigned char **out, size_t *outlen, X509 *x, size_t chainidx,
    int *al, void *add_arg) {
    /* only include SCTs in the end-entity certificate */
    if (context == SSL_EXT_TLS1_3_CERTIFICATE && chainidx != 0) {
        return 0;
    }
#  else
int ngx_ssl_ct_ext_cb(SSL *s, unsigned int ext_type, const unsigned char **out,
    size_t *outlen, int *al, void *add_arg) {
    X509 *x = NULL;
#  endif

    if (!x) {
        /* get the cert OpenSSL chose to use for this connection */
        int result = SSL_set_current_cert(s, SSL_CERT_SET_SERVER);
        if (result == 2) {
            /*
             * Anonymous/PSK cipher suites don't use certificates, so don't attempt
             * to add the SCT extension to the ServerHello.
             */
            return 0;
        } else if (result != 1) {
            ngx_connection_t *c = ngx_ssl_get_connection(s);
            ngx_log_error(NGX_LOG_WARN, c->log, 0, "SSL_set_current_cert failed");
            return -1;
        }

        x = SSL_get_certificate(s);
        if (!x) {
            /* as above */
            return 0;
        }
    }

    /* get sct_list for the cert OpenSSL chose to use for this connection */
    ngx_ssl_ct_ext *sct_list = X509_get_ex_data(x, ngx_ssl_ct_sct_list_index);

    if (sct_list) {
        *out    = sct_list->buf;
        *outlen = sct_list->len;
        return 1;
    } else {
        return 0;
    }
}
#endif

static ngx_ssl_ct_ext *ngx_ssl_ct_read_static_sct(ngx_conf_t *cf,
    ngx_str_t *dir, u_char *file, size_t file_len,
    ngx_ssl_ct_ext *sct_list) {
    int ok = 0;

    /* join dir and file name */
    size_t path_len = dir->len + file_len + 2;
    u_char *path = ngx_pcalloc(cf->pool, path_len);
    if (path == NULL) {
        return NULL;
    }

    u_char *path_end = ngx_cpystrn(path, dir->data, dir->len + 1);
    *path_end++ = '/';
    ngx_cpystrn(path_end, file, file_len + 1);

    /* open file */
    ngx_fd_t fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_open_file_n " \"%s\" failed", path);
        ngx_pfree(cf->pool, path);
        return NULL;
    }

    /* get file size */
    ngx_file_info_t stat;
    if (ngx_fd_info(fd, &stat) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_fd_info_n " \"%s\" failed", path);
        goto out;
    }

    const size_t sct_len = ngx_file_size(&stat);
    if (sct_len == 0) {
        ok = 1;
        goto out;
    }

    const size_t len_pos = sct_list->len;
    size_t sct_pos = len_pos + 2;

    /* reserve two bytes for the length and sct_len bytes for the SCT. */
    const size_t sct_and_len_size = sct_len + 2;

    if (sct_and_len_size < sct_len ||
        sct_list->len + sct_and_len_size < sct_list->len ||
        sct_list->len + sct_and_len_size > NGX_SSL_CT_EXT_MAX_LEN) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
            "sct_list structure exceeds maximum length");
        goto out;
    }
    sct_list->len += sct_and_len_size;

    /* read the SCT from disk */
    size_t to_read = sct_len;
    while (to_read > 0) {
        ssize_t n = ngx_read_fd(fd, sct_list->buf + sct_pos, to_read);
        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
                ngx_read_fd_n " \"%s\" failed", path);
            goto out;
        }

        to_read -= n;
        sct_pos += n;
    }

    /* fill in the length bytes and return */
    sct_list->buf[len_pos] = sct_len >> 8;
    sct_list->buf[len_pos + 1] = sct_len;
    ok = 1;

out:
    if (ngx_close_file(fd) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_close_file_n " \"%s\" failed", path);
    }
    ngx_pfree(cf->pool, path);

    if (!ok) {
        return NULL;
    }
    return sct_list;
}

ngx_ssl_ct_ext *ngx_ssl_ct_read_static_scts(ngx_conf_t *cf, ngx_str_t *path) {
    /* resolve relative paths */
    if (ngx_conf_full_name(cf->cycle, path, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            "ngx_conf_full_name \"%V\" failed");
        return NULL;
    }

    /* allocate sct_list structure */
    ngx_ssl_ct_ext *sct_list = ngx_pcalloc(cf->pool, sizeof(*sct_list));
    if (!sct_list) {
        return NULL;
    }

    /* reserve the first two bytes for the length */
    sct_list->len += 2;

    /* open directory */
    ngx_dir_t dir;
    if (ngx_open_dir(path, &dir) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_open_dir_n " \"%V\" failed", path);
        ngx_pfree(cf->pool, sct_list);
        return NULL;
    }

    /* iterate through all files */
    for (;;) {
        ngx_set_errno(NGX_ENOMOREFILES);

        if (ngx_read_dir(&dir) != NGX_OK) {
            ngx_err_t err = ngx_errno;

            if (err == NGX_ENOMOREFILES) {
                break;
            } else {
                ngx_log_error(NGX_LOG_EMERG, cf->log, err,
                    ngx_read_dir_n " \"%V\" failed", path);
                ngx_pfree(cf->pool, sct_list);
                return NULL;
            }
        }

        /* skip dotfiles */
        size_t file_len = ngx_de_namelen(&dir);
        u_char *file = ngx_de_name(&dir);
        if (file[0] == '.') {
            continue;
        }

        /* skip files unless the extension is .sct */
        u_char *file_ext = (u_char *) ngx_strrchr(file, '.');
        if (!file_ext || ngx_strcmp(file_ext, ".sct")) {
            continue;
        }

        /* add the .sct file to the sct_list */
        if (!ngx_ssl_ct_read_static_sct(cf, path, file, file_len, sct_list)) {
            /* ngx_ssl_ct_read_static_sct calls ngx_log_error */
            ngx_pfree(cf->pool, sct_list);
            return NULL;
        }
    }

    /* close directory */
    if (ngx_close_dir(&dir) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
            ngx_close_dir_n " \"%V\" failed", path);
        ngx_pfree(cf->pool, sct_list);
        return NULL;
    }

    /* fill in the length bytes and return */
    size_t sct_list_len = sct_list->len - 2;
    if (sct_list_len > 0) {
        sct_list->buf[0] = sct_list_len >> 8;
        sct_list->buf[1] = sct_list_len;
    } else {
        sct_list->len = 0;
    }
    return sct_list;
}
