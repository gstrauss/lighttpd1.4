/*
 * mod_h264_streaming - pseudo-streaming Quicktime/MPEG4 files
 *
 * Copyright(c) 2020 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * QuickTime File Format Specification
 * https://web.archive.org/web/20090825113042/http://developer.apple.com/documentation/QuickTime/QTFF/QTFFPreface/qtffPreface.html
 * https://web.archive.org/web/20090529194000/http://developer.apple.com/documentation/QuickTime/QTFF/qtff.pdf
 *
 * The underlying h264 support files (supporting function callouts to mp4_*()):
 */
/*******************************************************************************
 Copyright (C) 2007-2009 CodeShop B.V.

 Licensing
 The Streaming Module is licened under a Creative Commons License. It
 allows you to use, modify and redistribute the module, but only for
 *noncommercial* purposes. For corporate use, please apply for a
 commercial license.

 Creative Commons License:
 http://creativecommons.org/licenses/by-nc-sa/3.0/

 Commercial License for H264 Streaming Module:
 http://h264.code-shop.com/trac/wiki/Mod-H264-Streaming-License-Version2

 Commercial License for Smooth Streaming Module:
 http://smoothstreaming.code-shop.com/trac/wiki/Mod-Smooth-Streaming-License
******************************************************************************/

#include "first.h"

#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "array.h"
#include "buffer.h"
#include "etag.h"
#include "log.h"
#include "http_chunk.h"
#include "http_header.h"
#include "response.h"
#include "stat_cache.h"

#include "plugin.h"

#include "h264/mp4_process.h"
#include "h264/moov.h"
#include "h264/output_bucket.h"
#ifdef BUILDING_H264_STREAMING
#define X_MOD_STREAMING_KEY X_MOD_H264_STREAMING_KEY
#define X_MOD_STREAMING_VERSION X_MOD_H264_STREAMING_VERSION
#endif

typedef struct {
    const array *extensions;
    unsigned short buffer_seconds;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;

typedef struct {
    struct mp4_split_options_t* options;
    unsigned short buffer_seconds;
} handler_ctx;

static handler_ctx * handler_ctx_init(unsigned short buffer_seconds) {
    handler_ctx * hctx = ck_calloc(1, sizeof(*hctx));
    hctx->options = mp4_split_options_init();
    hctx->buffer_seconds = buffer_seconds;
    return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
    mp4_split_options_exit(hctx->options);
    free(hctx);
}

INIT_FUNC(mod_h264_streaming_init) {
    return ck_calloc(1, sizeof(plugin_data));
}

static void mod_h264_streaming_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* h264-streaming.extensions */
        pconf->extensions = cpv->v.a;
        break;
      case 1: /* h264-streaming.buffer-seconds */
        pconf->buffer_seconds = cpv->v.shrt;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_h264_streaming_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_h264_streaming_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_h264_streaming_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_h264_streaming_merge_config(&p->conf,
                                            p->cvlist + p->cvlist[i].v.u2[0]);
    }
}

SETDEFAULTS_FUNC(mod_h264_streaming_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("h264-streaming.extensions"),
        T_CONFIG_ARRAY_VLIST,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("h264-streaming.buffer-seconds"),
        T_CONFIG_SHORT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_h264_streaming"))
        return HANDLER_ERROR;

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_h264_streaming_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

URIHANDLER_FUNC(mod_h264_streaming_path_handler) {
    plugin_data *p = p_d;

    if (NULL != r->handler_module) return HANDLER_GO_ON;
    if (buffer_is_empty(&r->physical.path)) return HANDLER_GO_ON;

    mod_h264_streaming_patch_config(r, p);

    if (NULL == p->conf.extensions
        || NULL == array_match_value_suffix(p->conf.extensions, &r->uri.path)) {
        return HANDLER_GO_ON;
    }

    // Range requests are currently not supported, so let mod_staticfile
    // handle it. Obviously the 'start' parameter doesn't work with
    // mod_staticfile and so the movie always plays from the beginning,
    // but at least it makes streaming and seeking in VLC work.
    if (r->conf.range_requests && light_btst(r->rqst_htags, HTTP_HEADER_RANGE))
        return HANDLER_GO_ON;

    stat_cache_entry *sce = stat_cache_get_entry(&r->physical.path);
    if (NULL == sce) {
        r->http_status = 403;
        return HANDLER_FINISHED;
    }

    http_header_response_set(r, HTTP_HEADER_CONTENT_TYPE,
                             CONST_STR_LEN("Content-Type"),
                             CONST_STR_LEN("video/mp4"));

    http_header_response_set(r, HTTP_HEADER_OTHER,
                             CONST_STR_LEN(X_MOD_STREAMING_KEY),
                             CONST_STR_LEN(X_MOD_STREAMING_VERSION));

    const buffer *etag = (0 != r->conf.etag_flags)
      ? stat_cache_etag_get(sce, r->conf.etag_flags)
      : NULL;
    if (!buffer_string_is_empty(etag)) {
        const buffer *b = etag;
        if (!buffer_string_is_empty(&r->uri.query)) {
            b = &r->physical.etag;
            buffer_copy_buffer(&r->physical.etag, etag);
            buffer_append_string_buffer(&r->physical.etag, &r->uri.query);
            etag_mutate(&r->physical.etag, &r->physical.etag);
        }
        http_header_response_set(r, HTTP_HEADER_ETAG,
                                 CONST_STR_LEN("ETag"),
                                 CONST_BUF_LEN(b));
    }

    const buffer *mtime = strftime_cache_get(sce->st.st_mtime);
    http_header_response_set(r, HTTP_HEADER_LAST_MODIFIED,
                             CONST_STR_LEN("Last-Modified"),
                             CONST_BUF_LEN(mtime));

    if (HANDLER_FINISHED == http_response_handle_cachable(r, mtime))
        return HANDLER_FINISHED;

    handler_ctx *hctx = handler_ctx_init(p->conf.buffer_seconds);
    r->plugin_ctx[p->id] = hctx;

    if (buffer_string_is_empty(&r->uri.query)
        && !mp4_split_options_set(hctx->options, CONST_BUF_LEN(&r->uri.query))){
        r->http_status = 403;
        return HANDLER_FINISHED;
    }

    struct bucket_t *buckets = NULL;
    int verbose = 0;
    r->http_status =
      mp4_process(r->physical.path.ptr, (uint64_t)sce->st.st_size,
                  verbose, &buckets, hctx->options);

    if (r->http_status != 200) {
        if (buckets)
            buckets_exit(buckets);
        return HANDLER_FINISHED;
    }

    r->resp_body_finished = 1;

    if (!buckets)
        return HANDLER_FINISHED;

    if (hctx->buffer_seconds && hctx->buffer_seconds < hctx->options->seconds) {
        off_t moov_offset = hctx->options->byte_offsets[hctx->buffer_seconds];
        r->conf.bytes_per_second = (unsigned int)moov_offset;
    }

    struct bucket_t *bucket = buckets;
    do {
        switch (bucket->type_) {
          case BUCKET_TYPE_MEMORY:
            http_chunk_append_mem(r, bucket->buf_, (size_t)bucket->size_);
            break;
          case BUCKET_TYPE_FILE:
            http_chunk_append_file_range(r, &r->physical.path,
                                         (off_t)bucket->offset_,
                                         (off_t)bucket->size_);
            break;
          default:
            break;
        }
    } while ((bucket = bucket->next_) != buckets);
    buckets_exit(buckets);

    return HANDLER_FINISHED;
}

TRIGGER_FUNC(mod_h264_streaming_trigger) {
    plugin_data *p = p_d;

    for (uint32_t i = 0; i < srv->conns.used; ++i) {
        connection *con = srv->conns.ptr[i];
        request_st * const r = &con->request;
        handler_ctx *hctx = r->plugin_ctx[p->id];

        /* check if h264 request and if bandwidth shaping is enabled */
        if (hctx == NULL || !hctx->buffer_seconds)
            continue;

        /* remove throttle when near the end */
        int t_diff = log_epoch_secs - con->connection_start;
        if (t_diff + hctx->buffer_seconds >= hctx->options->seconds) {
            r->conf.bytes_per_second = 0;
            continue;
        }

        off_t moov_offset =
          hctx->options->byte_offsets[t_diff + hctx->buffer_seconds];

        r->conf.bytes_per_second = (con->bytes_written < moov_offset)
          ? (moov_offset - con->bytes_written)
          : 32768; /* throttle connection; TCP send buffers are full */
    }

    return HANDLER_GO_ON;
}

REQUEST_FUNC(mod_h264_streaming_cleanup) {
    void ** const hctx = r->plugin_ctx+((plugin_data_base *)p_d)->id;
    if (*hctx) { handler_ctx_free(*hctx); *hctx = NULL; }
    return HANDLER_GO_ON;
}


int mod_h264_streaming_plugin_init(plugin *p);
int mod_h264_streaming_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "h264_streaming";

    p->init        = mod_h264_streaming_init;
    p->set_defaults= mod_h264_streaming_set_defaults;

    p->handle_physical  = mod_h264_streaming_path_handler;
    p->handle_trigger   = mod_h264_streaming_trigger;
    p->handle_request_reset = mod_h264_streaming_cleanup;

    return 0;
}
