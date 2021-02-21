/*
 * mod_csrf - (anti-) cross-site request forgery (CSRF) token validation
 *
 * Copyright(c) 2021 Glenn Strauss gstrauss()gluelogic.com  All rights reserved
 * License: BSD 3-clause (same as lighttpd)
 *
 * Reference:
 *   https://en.wikipedia.org/wiki/Cross-site_request_forgery
 *   https://en.wikipedia.org/wiki/Session_fixation
 *   https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 *
 * Warning:
 * Effective CSRF mitigation requires coordination of multiple actors.
 * The client and the backend appliation are outside of the web server purview.
 * There is no one-size-fits-all solution.  Mismatched assumptions and
 * protection settings may result in ineffective CSRF mitigation!
 *
 * lighttpd mod_csrf does not attempt parse query string or request body (which
 * might not yet have been received) for POST application/x-www-form-urlencoded
 * params.  An application which adds (hidden) fields in web forms should parse
 * and validate those fields itself when processing the submitted web form,
 * instead of using mod_csrf.
 *
 * lighttpd mod_csrf attempts the HMAC Based Token Pattern
 *   and recommends integrating with "sesscookie" csrf.opts
 *   (See cheatsheetseries.owasp.org link in References above)
 *
 * csrf.protect => "enable"
 *   default: "disable"
 *   Enforce token present and valid, or else reject request with 403 Forbidden.
 *   e.g. $HTTP["request-method"] == "POST" { csrf.protect = "enable" }
 *
 * csrf.opts
 *   default: (empty list) (disabled)
 *   (While these options each have defaults, csrf.opts must exist with at
 *    least one option specified to enable token generation and csrf.protect)
 *
 * "header" => "x-xsrf-token"
 *   default: "x-xsrf-token"
 *   Name of HTTP header containing token
 *
 * "ttl" => 600
 *   default: 600 (600 seconds == 10 minutes)
 *   lifetime of token
 *   (If set to 0, token checking and token generation is disabled.)
 *
 * "algorithm" => "sha256" | "sha1" | "md5"
 *   default: "sha256"
 *   HMAC algorithm.  Use "sha256".  SHA1 and MD5 are weak and insecure.
 *   "sha1" or "md5" should be used only if lighttpd is not built against
 *   a crypto library supporting SHA256.
 *
 * "secret" => "..."
 *   default: 32-bytes of random data
 *   Secret to use with HMAC algorithm.  Must be at least 32 chars if specified.
 *   Must be set and synchronized if site has multiple web server instances, and
 *   request might be redirected (or load balanced) to more than one web server.
 *   e.g. $ pwgen -s 32 1
 *
 * "sesscookie" => "..."
 *   default: (none)
 *   Name of session cookie.  If set, session id is included in HMAC.
 *   If sesscookie is configured but not found, token validation fails.
 *   To mitigate against session fixation attacks, the application is
 *   responsible for changing the Session ID when the user logs in.)
 *
 * "xsrfcookie" => "..."
 *   default: (none)
 *   Name of XSRF token cookie, e.g. "xsrf-token"
 *   If set, Set-Cookie will be sent with token value, in addition to
 *   csrf.opts "header" response header with token value.  Admin is
 *   *separately* responsible for using mod_setenv to set appropriate
 *   CORS headers according to site policy, e.g.
 *     Access-Control-Allow-Credentials: true
 *     Access-Control-Allow-Origin: example.com   # must not be '*'
 *     Access-Control-Allow-Headers: ...
 *
 * "auth-user" => "enable"
 *   default: "enable"
 *   Fallback if sesscookie is not configured.  Not used if sesscookie is set.
 *   Require that user be authenticated and REMOTE_USER be included in HMAC.
 *   (Restricts token to use by specific authenticated user)
 *   REMOTE_USER is usually set by mod_auth
 *     (mod_auth must be listed before mod_csrf in server.modules)
 *
 * "referer" => "enable"
 *   default: "disable"
 *   Require that Referer request header exist and matches same origin
 *   (applies when csrf.protect = "enable")
 *   (Note: Depending on client browser settings and on proxy middleboxes,
 *    Referer header might not be sent or might be stripped from request
 *    for privacy reasons, so this option should be used only when the
 *    intended clients will send Referer, and Referer will not be stripped
 *    by any intermediary.)
 *   (This setting is not necessary if "sesscookie" is used here, cookie created
 *    with SameSite=Strict attribute, and clients support SameSite=Strict)
 *
 * csrf.opts should be configured only on paths with dynamically-generated
 * content, and *should not* be configured on static resources except possibly
 * for specific static pages containing web forms with target (POST) locations
 * with csrf.protect = "enable".  Otherwise, resources are unnecessarily wasted
 * checking and/or regenerating the HMAC.
 * e.g. $HTTP["url"] =~ "^/cgi-bin/" { csrf.opts = ( ... ) }
 *   or $HTTP["url"] !~ "^/static/"  { csrf.opts = ( ... ) }
 * csrf.opts should be configured only on paths that are not cachable, since the
 * response header (and possibly future cookie) should be specifc to the session
 *
 *
 * Technical details: (internals)
 *
 * Token: base64-encoding of "message" and a checksum (HMAC)
 *
 * Token protects message + extra data:
 * "message":
 * - 1 byte: version (0x01)
 * - 8 bytes: uint64_t big endian timestamp in seconds since epoch
 * "extra data":
 *   session id or REMOTE_USER (if configured; can be empty)
 *
 * future: if sesscookie and auth-user are both disabled, might consider adding
 * client IP as salt, but then might also include client IP in msg since client
 * connecting through a proxy or mobile users might reconnect from different IP.
 *
 * future: might add option to set token in environment (CSRF_TOKEN) via hook
 * handle_request_env (when csrf.protect = "disable") so that backend could
 * generate web form and insert token in hidden form field (or could Set-Cookie
 * xsrf-token).  Javascript on client could insert field value into request
 * header when form is submitted via AJAX XMLHttpRequest.
 *
 * future: might add option to require matching request header and xsrfcookie
 *
 * future: might replace csrf.protect => "enable" with "always enabled" unless
 * the request method is OPTIONS, in which case, treat as a CORS preflight and
 * return header and xsrfcookie, if configured.
 */
#include "first.h"

#include <arpa/inet.h>  /* htonl() */
#include <stdlib.h>
#include <string.h>

#include "sys-crypto-md.h"
#include "algo_hmac.h"
#include "rand.h"

#include "plugin.h"
#include "ck.h"
#include "base.h"
#include "base64.h"
#include "log.h"
#include "buffer.h"
#include "burl.h"
#include "request.h"
#include "mod_auth_api.h"
#include "http_header.h"

#define TOKEN_DEFAULT_TTL 600 /* 600 seconds == 10 minutes */
#define SECRET_SIZE 32 /* secret to automatically generate as fallback */
static char csrf_secret[SECRET_SIZE+1];
static const buffer csrf_secretb = { csrf_secret, sizeof(csrf_secret), 0 };
static const buffer csrf_headerb = { CONST_STR_LEN("x-xsrf-token"), 0 };

typedef int(*hmac_fn_t)(unsigned char *, const void *, uint32_t, const unsigned char *, uint32_t);

typedef struct {
    const buffer *header;
    const buffer *secret;
    const buffer *sesscookie;
    const buffer *xsrfcookie;
    hmac_fn_t hmac_fn;
    uint32_t dlen; /* digest length */
    uint32_t ttl;
    unsigned int referer:1;
    unsigned int auth_user:1;
} csrf_opts;

typedef struct {
    const csrf_opts *opts;
    int protect;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;


INIT_FUNC(mod_csrf_init)
{
    return ck_calloc(1, sizeof(plugin_data));
}


FREE_FUNC(mod_csrf_free)
{
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* csrf.opts */
                if (cpv->vtype == T_CONFIG_LOCAL) free(cpv->v.v);
                break;
              default:
                break;
            }
        }
    }

    ck_memzero(csrf_secret, sizeof(csrf_secret));
}


static void
mod_csrf_merge_config_cpv (plugin_config * const pconf,
                           const config_plugin_value_t * const cpv)
{
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* csrf.opts */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->opts = cpv->v.v;
        break;
      case 1: /* csrf.protect */
        pconf->protect = (0 != cpv->v.u);
        break;
      default:/* should not happen */
        return;
    }
}


static void
mod_csrf_merge_config (plugin_config * const pconf,
                       const config_plugin_value_t *cpv)
{
    do {
        mod_csrf_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}


static void
mod_csrf_patch_config (request_st * const r, plugin_data * const p)
{
    memcpy(&p->conf, &p->defaults, sizeof(plugin_config));
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_csrf_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
    }
}


static csrf_opts *
mod_csrf_parse_opts (server * const srv, const array * const a)
{
    csrf_opts * const opts = ck_calloc(1, sizeof(*opts));

  #ifdef USE_LIB_CRYPTO
    opts->hmac_fn = li_hmac_sha256;
    opts->dlen = SHA256_DIGEST_LENGTH;
  #else
    opts->hmac_fn = li_hmac_md5;
    opts->dlen = MD5_DIGEST_LENGTH;
  #endif
    opts->ttl = TOKEN_DEFAULT_TTL;
    opts->header = &csrf_headerb;
    /* empty user not allowed by default to prevent mistakes in server.modules
     * mod_auth/mod_csrf ordering */
    opts->auth_user = 1;

    const buffer *algo = NULL;

    for (uint32_t i = 0; i < a->used; ++i) {
        data_unset * const du = a->data[i];
        if (buffer_eq_slen(&du->key, CONST_STR_LEN("header"))
            && du->type == TYPE_STRING) {
            opts->header = &((data_string *)du)->value;
            if (HTTP_HEADER_OTHER
                != http_header_hkey_get(CONST_BUF_LEN(opts->header))) {
                log_error(srv->errh, __FILE__, __LINE__,
                  "internal id for csrf.opts \"header\" (%s) is unexpected",
                  opts->header->ptr);
                free(opts);
                return NULL;
            }
        }
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("sesscookie"))
            && du->type == TYPE_STRING)
            opts->sesscookie = &((data_string *)du)->value;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("xsrfcookie"))
                 && du->type == TYPE_STRING)
            opts->xsrfcookie = &((data_string *)du)->value;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("secret"))
                 && du->type == TYPE_STRING)
            opts->secret = &((data_string *)du)->value;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("algorithm"))
                 && du->type == TYPE_STRING)
            algo = &((data_string *)du)->value;
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("ttl")))
            opts->ttl = config_plugin_value_to_int32(du, TOKEN_DEFAULT_TTL);
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("referer")))
            opts->referer = config_plugin_value_tobool(du, 0);
        else if (buffer_eq_slen(&du->key, CONST_STR_LEN("auth-user")))
            opts->auth_user = config_plugin_value_tobool(du, 1);
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "unexpected key or value type for csrf.opts \"%s\"", du->key.ptr);
            /*(ignore error; continue using default values)*/
        }
    }

    if (algo) {
        if (buffer_eq_slen(algo, CONST_STR_LEN("sha256"))) {
            opts->hmac_fn = li_hmac_sha256;
            opts->dlen = SHA256_DIGEST_LENGTH;
        }
        else if (buffer_eq_slen(algo, CONST_STR_LEN("sha1"))) {
            opts->hmac_fn = li_hmac_sha1;
            opts->dlen = SHA_DIGEST_LENGTH;
        }
        else if (buffer_eq_slen(algo, CONST_STR_LEN("md5"))) {
            opts->hmac_fn = li_hmac_md5;
            opts->dlen = MD5_DIGEST_LENGTH;
        }
        else {
            log_error(srv->errh, __FILE__, __LINE__,
              "invalid csrf.opts \"algorithm\" => \"%s\"", algo->ptr);
            /*(ignore error; continue using default value)*/
        }
      #ifndef USE_LIB_CRYPTO
        if (opts->hmac_fn != li_hmac_md5) {
            log_error(srv->errh, __FILE__, __LINE__,
              "unsupported csrf.opts \"algorithm\" => \"%s\"", algo->ptr);
            /*free(opts);*/
            /*return NULL;*/
            /* proceed to allow config to load for other tests */
            /*(use of unsupported algorithm will result in failure at runtime)*/
        }
      #endif
    }

    if (opts->secret) {
        if (buffer_clen(opts->secret) < SECRET_SIZE) {
            log_error(srv->errh, __FILE__, __LINE__,
                      "csrf.opts \"secret\" too short (< %d)", SECRET_SIZE);
            free(opts);
            return NULL;
        }
    }
    else if (0 != opts->ttl) {
        opts->secret = &csrf_secretb;
        if (csrf_secret[0] == '\0')
            li_rand_pseudo_bytes((unsigned char *)csrf_secret, SECRET_SIZE);
    }

    return opts;
}


SETDEFAULTS_FUNC(mod_csrf_set_defaults)
{
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("csrf.opts"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("csrf.protect"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_csrf"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* csrf.opts */
                cpv->v.v = mod_csrf_parse_opts(srv, cpv->v.a);
                if (NULL == cpv->v.v)
                    return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              case 1: /* csrf.protect */
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    p->defaults.protect = 1; /* protect by default (when opts configured) */

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_csrf_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}


static void
mod_csrf_set_token (request_st * const r, const csrf_opts * const opts,
                    const char * const extra, const uint32_t elen)
{
    /* msg4[] must be >= +3 larger than largest binary digest used
     *   (for SHA256:  8 + 3 = 11)
     *   (for SHA512: 16 + 3 = 19)
     * create msg4[] large enough to additionally hold 1024 char extra, which is
     * appended into single string for ease of HMAC() without HMAC_Update()) */
    uint32_t msg4[3+256];
    /* store time in big endian */
    const uint64_t exp_ts = (uint64_t)log_epoch_secs + opts->ttl;
    msg4[1] = htonl((exp_ts >> 32) & 0xFFFFFFFF);
    msg4[2] = htonl((exp_ts      ) & 0xFFFFFFFF);

    unsigned char * const msg = ((unsigned char *)msg4)+3;
    msg[0] = 1; /* CSRF token "version" */

    const uint32_t mlen = 9;
    if (elen) {
        if (elen > sizeof(msg4)-12) return;/*(extra too long for fixed buffer)*/
        memcpy(msg4+3, extra, elen);
    }

    /*(append digest to msg+mlen, overwriting/replacing extra in string)*/
    if (!opts->hmac_fn(msg+mlen, CONST_BUF_LEN(opts->secret), msg, mlen+elen)) {
        log_error(r->conf.errh, __FILE__, __LINE__, "HMAC() failed");
        return;
    }

    buffer * const vb =
      http_header_response_set_ptr(r, HTTP_HEADER_OTHER,
                                   CONST_BUF_LEN(opts->header));
    buffer_append_base64_encode_no_padding(vb, msg, mlen + opts->dlen,
                                           BASE64_URL);

    if (!buffer_string_is_empty(opts->xsrfcookie)) {
        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        buffer_append_str3(tb, BUF_PTR_LEN(opts->xsrfcookie),
                               CONST_STR_LEN("="),
                               BUF_PTR_LEN(vb));

        if (!buffer_string_is_empty(&r->uri.authority)) {
            buffer_append_string_len(tb, CONST_STR_LEN("; Domain="));
            buffer_append_string_encoded(tb, CONST_BUF_LEN(&r->uri.authority),
                                         ENCODING_REL_URI);
        }

        buffer_append_string_len(tb,
          CONST_STR_LEN("; Path=/; SameSite=Strict; Max-Age="));
        buffer_append_int(tb, opts->ttl);

        if (buffer_is_equal_string(&r->uri.scheme, CONST_STR_LEN("https")))
            buffer_append_string_len(tb, CONST_STR_LEN("; Secure"));

        /* HttpOnly attribute *is not* set so that cookie can be accessed by
         * client-side javascript frameworks using Cookie-to-Header pattern */

        http_header_response_insert(r, HTTP_HEADER_SET_COOKIE,
                                    CONST_STR_LEN("Set-Cookie"),
                                    CONST_BUF_LEN(tb));
    }
}


typedef enum {
    TOKEN_CHECK_OK
   ,TOKEN_CHECK_OK_RENEW
   ,TOKEN_CHECK_MISSING
   ,TOKEN_CHECK_EXPIRED
   ,TOKEN_CHECK_INVALID
   ,TOKEN_CHECK_FAILED
} token_check_result;


static token_check_result
mod_csrf_validate_token (request_st * const r, const csrf_opts * const opts,
                         const char * const extra, const uint32_t elen)
{
    const buffer * const token =
      http_header_request_get(r, HTTP_HEADER_OTHER,
                              CONST_BUF_LEN(opts->header));
    if (NULL == token)
        return TOKEN_CHECK_MISSING;

    buffer * const tb = r->tmp_buf;
    buffer_clear(tb);
    if (!buffer_append_base64_decode(tb, CONST_BUF_LEN(token), BASE64_URL))
        return TOKEN_CHECK_INVALID;

    /* CSRF token "version" check; require version 1 format */
    const uint32_t mlen = 9;
    if (buffer_clen(tb) != mlen + opts->dlen)
        return TOKEN_CHECK_INVALID;
    const unsigned char * const msg = (unsigned char *)tb->ptr;
    if (msg[0] != 1)
        return TOKEN_CHECK_INVALID;
    uint64_t ts = 0;
    for (int i = 1; i < 9; ++i) /* parse timestamp */
        ts = (ts << 8) | msg[i];
    const uint64_t cur_ts = (uint64_t)log_epoch_secs;
    if (ts < cur_ts)
        return TOKEN_CHECK_EXPIRED; /* expired (note: HMAC not verified) */
    const token_check_result rc = (ts > cur_ts + (opts->ttl >> 2))
      ? TOKEN_CHECK_OK
      : TOKEN_CHECK_OK_RENEW;

    /* NOTE: digest[] must be large enough to hold output
     * (SHA256 digest: 32 bytes; SHA512 digest: 64 bytes) */
    /* save input digest (follows msg) and reconstruct msg + extra
     * into single string for ease of HMAC() without HMAC_Update()) */
    char input[64];
    unsigned char digest[64];
  #ifdef __COVERITY__
    force_assert(opts->dlen <= sizeof(input));
    force_assert(opts->dlen <= sizeof(digest));
  #endif
    memcpy(input, msg+mlen, opts->dlen);
    buffer_string_set_length(tb, mlen);
    buffer_append_string_len(tb, extra, elen);
    return opts->hmac_fn(digest, CONST_BUF_LEN(opts->secret),
                         (unsigned char *)CONST_BUF_LEN(tb))
        && ck_memeq_const_time_fixed_len(input, (char *)digest, opts->dlen)
      ? rc /* TOKEN_CHECK_OK or TOKEN_CHECK_OK_RENEW */
      : TOKEN_CHECK_FAILED; /* digest mismatch */
}


__attribute_pure__
static int
mod_csrf_same_origin (const request_st * const r, const buffer * const b)
{
    if (NULL == b) return 0;
    const uint32_t blen = buffer_clen(b);
    const uint32_t slen = buffer_clen(&r->uri.scheme);
    const uint32_t alen = buffer_clen(&r->uri.authority);
    const char * const p = b->ptr;
    return (blen >= slen + 3 + alen)
        && 0 == memcmp(p, r->uri.scheme.ptr, slen)
        && p[slen+1] == ':' && p[slen+2] == '/' && p[slen+3] == '/'
        && 0 == memcmp(p+slen+3, r->uri.authority.ptr, alen)
        && (p[slen+3+alen] == '/' || p[slen+3+alen] == '\0');
}


__attribute_pure__
static int
mod_csrf_referer_same_origin (const request_st * const r)
{
    const buffer * const referer =
      http_header_request_get(r, HTTP_HEADER_REFERER, CONST_STR_LEN("Referer"));
    return mod_csrf_same_origin(r, referer);
}


__attribute_cold__
static handler_t
mod_csrf_403 (request_st * const r)
{
    r->http_status = 403;
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}


URIHANDLER_FUNC(mod_csrf_uri_handler)
{
    switch (r->http_method) {
      case HTTP_METHOD_CONNECT:
      case HTTP_METHOD_TRACE:
        return HANDLER_GO_ON;
      case HTTP_METHOD_OPTIONS:
        if (r->uri.path.ptr[0] == '*' && r->uri.path.ptr[1] == '\0')
            return HANDLER_GO_ON;
        break;
      default:
        break;
    }

    plugin_data * const p = p_d;
    mod_csrf_patch_config(r, p);
    const csrf_opts * const opts = p->conf.opts;
    if (NULL == opts || 0 == opts->ttl) return HANDLER_GO_ON;

    /* check Referer (if configured) */
    if (p->conf.protect && opts->referer && !mod_csrf_referer_same_origin(r))
        return mod_csrf_403(r);

    const char *extra = NULL;
    uint32_t elen = 0;

    /* retrieve session cookie (if configured) */
    if (!buffer_string_is_empty(opts->sesscookie)) {
        const buffer * const vb =
          http_header_request_get(r,HTTP_HEADER_COOKIE,CONST_STR_LEN("Cookie"));
        if (NULL != vb) {
            /* parse cookie (fuzzy; not precise since using strstr() below) */
            const char *s = strstr(vb->ptr, opts->sesscookie->ptr);
            if (NULL != s) {
                s += buffer_clen(opts->sesscookie);
                while (*s == ' ' || *s == '\t') ++s; /* skip WS */
                if (*s == '=') { /* matched sesscookie */
                    do { ++s; } while (*s == ' ' || *s == '\t'); /* skip WS */
                    extra = s;
                    while (*s && *s != ';' && *s != ' ' && *s != '\t') ++s;
                    elen = (uint32_t)(s - extra);
                }
            }
        }
        if (0 == elen)
            return !p->conf.protect ? HANDLER_GO_ON : mod_csrf_403(r);
    }

    /* retrieve REMOTE_USER (if configured) */
    if (0 == elen && opts->auth_user) {
        const buffer * const vb =
          http_header_env_get(r, CONST_STR_LEN("REMOTE_USER"));
        if (NULL != vb) {
            extra = vb->ptr;
            elen = buffer_clen(vb);
        }
        if (0 == elen)
            return !p->conf.protect ? HANDLER_GO_ON : mod_csrf_403(r);
    }

    /* validate token */
    const token_check_result result =
      mod_csrf_validate_token(r, opts, extra, elen);

    if (TOKEN_CHECK_OK == result)
        return HANDLER_GO_ON;

    /* generate token */
    mod_csrf_set_token(r, opts, extra, elen);

    if (TOKEN_CHECK_OK_RENEW == result)
        return HANDLER_GO_ON;

    if (!p->conf.protect)
        return HANDLER_GO_ON;

    if (r->http_method == HTTP_METHOD_OPTIONS) /* e.g. CORS preflight request */
        return HANDLER_GO_ON;

    if (!buffer_string_is_empty(opts->xsrfcookie)
        && (opts->referer || mod_csrf_referer_same_origin(r))) {
        /* check Referer (if not already checked further above) and check
         * that SameSite=Strict domain-restricted xsrfcookie exists before
         * sending Retry-After in order to avoid getting into a retry loop
         * (loop might still occur if client fails to update request cookie) */
        /* (static page containing web form might contain javascript which
         *  creates xsrfcookie (even if invalid) to bootstrap) */
        const buffer * const vb =
          http_header_request_get(r,HTTP_HEADER_COOKIE,CONST_STR_LEN("Cookie"));
        if (NULL != vb) {
            /* parse cookie (fuzzy; not precise since using strstr() below) */
            const char *s = strstr(vb->ptr, opts->xsrfcookie->ptr);
            if (NULL != s) {
                s += buffer_clen(opts->xsrfcookie);
                while (*s == ' ' || *s == '\t') ++s; /* skip WS */
                if (*s == '=' /* matched xsrfcookie, sanity check new hdr set */
                    && http_header_response_get(r, HTTP_HEADER_OTHER,
                                                CONST_BUF_LEN(opts->header))
                    && (r->conf.http_parseopts & HTTP_PARSEOPT_URL_NORMALIZE)
                    && -2 != burl_normalize(&r->target_orig, r->tmp_buf,
                                            r->conf.http_parseopts)) {
                    http_header_response_set(r, HTTP_HEADER_LOCATION,
                                             CONST_STR_LEN("Location"),
                                             CONST_BUF_LEN(&r->target_orig));
                    http_header_response_set(r, HTTP_HEADER_OTHER,
                                             CONST_STR_LEN("Retry-After"),
                                             CONST_STR_LEN("0"));
                    r->handler_module = NULL;
                    r->http_status = !http_method_get_or_head(r->http_method)
                      ? 307  /* Temporary Redirect */
                      : 302; /* Found */
                    /* clients might not update request before retry after 503*/
                    /*r->http_status = 503;*/ /* Service Unavailable */
                    return HANDLER_FINISHED;
                }
            }
        }
    }

    return mod_csrf_403(r);
}


int mod_csrf_plugin_init(plugin *p);
int mod_csrf_plugin_init(plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "csrf";

    p->init             = mod_csrf_init;
    p->handle_uri_clean = mod_csrf_uri_handler;
    p->set_defaults     = mod_csrf_set_defaults;
    p->cleanup          = mod_csrf_free;

    return 0;
}
