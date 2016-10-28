#include "first.h"

#include <mysql.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "base.h"
#include "log.h"
#include "plugin.h"
#include "stat_cache.h"

/*
 * virtual host plugin using MySQL for domain to directory lookups
 */

typedef struct {
    MYSQL *dbconn;
    buffer *sqlquery;
    server *srv;
} vhostdb_config;

static void mod_vhost_db_dbconf_free (void *vdata)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    if (!dbconf) return;
    mysql_close(dbconf->dbconn);
    free(dbconf);
}

static int mod_vhost_db_dbconf_setup (server *srv, array *opts, void **vdata)
{
    buffer *sqlquery = NULL;
    const char *dbname=NULL, *user=NULL, *pass=NULL, *host=NULL, *sock=NULL;
    unsigned int port = 0;

    for (size_t i = 0; i < opts->used; ++i) {
        const data_string *ds = (data_string *)opts->data[i];
        if (ds->type == TYPE_STRING && !buffer_string_is_empty(ds->value)) {
            if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("sql"))) {
                sqlquery = ds->value;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("dbname"))) {
                dbname = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("user"))) {
                user = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("password"))) {
                pass = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("host"))) {
                host = ds->value->ptr;
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("port"))) {
                port = strtoul(ds->value->ptr, NULL, 10);
            } else if (buffer_is_equal_caseless_string(ds->key, CONST_STR_LEN("sock"))) {
                sock = ds->value->ptr;
            }
        }
    }

    /* required:
     * - sql    (sql query)
     * - dbname
     * - user
     *
     * optional:
     * - password, default: empty
     * - socket, default: mysql default
     * - hostname, if set overrides socket
     * - port, default: 3306
     */

    if (!buffer_string_is_empty(sqlquery)
        && dbname && *dbname && user && *user) {
        vhostdb_config *dbconf;
        MYSQL *dbconn = mysql_init(NULL);
        if (NULL == dbconn) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            "mysql_init() failed, exiting...");
            return -1;
        }

      #if MYSQL_VERSION_ID >= 50013
        /* in mysql versions above 5.0.3 the reconnect flag is off by default */
        {
            my_bool reconnect = 1;
            mysql_options(dbconn, MYSQL_OPT_RECONNECT, &reconnect);
        }
      #endif

        /* CLIENT_MULTI_STATEMENTS first appeared in 4.1 */ 
      #if MYSQL_VERSION_ID < 40100
        #ifndef CLIENT_MULTI_STATEMENTS
        #define CLIENT_MULTI_STATEMENTS 0
        #endif
      #endif
        if (!mysql_real_connect(dbconn, host, user, pass, dbname, port, sock,
                                CLIENT_MULTI_STATEMENTS)) {
            log_error_write(srv, __FILE__, __LINE__, "s",
                            mysql_error(dbconn));
            mysql_close(dbconn);
            return -1;
        }

        fd_close_on_exec(dbconn->net.fd);

        dbconf = (vhostdb_config *)calloc(1, sizeof(*dbconf));
        dbconf->dbconn = dbconn;
        dbconf->sqlquery = sqlquery;
        dbconf->srv = srv;
        *vdata = dbconf;
    }

    return 0;
}

static int mod_vhost_db_query (void *vdata, connection *con, buffer *docroot)
{
    vhostdb_config *dbconf = (vhostdb_config *)vdata;
    unsigned  cols;
    MYSQL_ROW row;
    MYSQL_RES *result;

    /*(reuse buffer for sql query before generating docroot result)*/
    buffer *sqlquery = docroot;
    buffer_string_set_length(sqlquery, 0); /*(also resets docroot (alias))*/

    for (char *b = dbconf->sqlquery->ptr, *d; *b; b = d+1) {
        if (NULL != (d = strchr(b, '?'))) {
            /* escape the uri.authority */
            unsigned long len;
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            buffer_string_prepare_append(sqlquery, buffer_string_length(con->uri.authority) * 2);
            len = mysql_real_escape_string(dbconf->dbconn,
                    sqlquery->ptr + buffer_string_length(sqlquery),
                    CONST_BUF_LEN(con->uri.authority));
            if ((unsigned long)~0 == len) return -1;
            buffer_commit(sqlquery, len);
        } else {
            d = dbconf->sqlquery->ptr + buffer_string_length(dbconf->sqlquery);
            buffer_append_string_len(sqlquery, b, (size_t)(d - b));
            break;
        }
    }

    if (mysql_real_query(dbconf->dbconn, CONST_BUF_LEN(sqlquery))) {
        log_error_write(dbconf->srv, __FILE__, __LINE__, "s",
                        mysql_error(dbconf->dbconn));
        buffer_string_set_length(docroot, 0); /*(reset buffer; no result)*/
        return -1;
    }

    buffer_string_set_length(docroot, 0); /*(reset buffer to store result)*/

    result = mysql_store_result(dbconf->dbconn);
    cols = mysql_num_fields(result);
    row = mysql_fetch_row(result);
    if (row && cols >= 1) {
        buffer_copy_string(docroot, row[0]);
    } /* else no such virtual host */

    mysql_free_result(result);
  #if MYSQL_VERSION_ID >= 40100
    while (0 == mysql_next_result(dbconf->dbconn)) ;
  #endif
    return 0;
}




typedef struct {
    void *vdata;
    array *options;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config conf;

    buffer *tmp_buf;
} plugin_data;

INIT_FUNC(mod_vhost_db_init) {
    plugin_data *p = calloc(1, sizeof(*p));
    p->tmp_buf = buffer_init();
    return p;
}

FREE_FUNC(mod_vhost_db_cleanup) {
    plugin_data *p = p_d;
    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (size_t i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];
            if (!s) continue;
            mod_vhost_db_dbconf_free(s->vdata);
            array_free(s->options);
            free(s);
        }
        free(p->config_storage);
    }
    buffer_free(p->tmp_buf);
    free(p);

    UNUSED(srv);
    return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_vhost_db_set_defaults) {
    plugin_data *p = p_d;

    config_values_t cv[] = {
        { "vhost.mysql",  NULL, T_CONFIG_ARRAY,  T_CONFIG_SCOPE_CONNECTION },
        { NULL,           NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
    };

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

    for (size_t i = 0; i < srv->config_context->used; ++i) {
        data_config const *config = (data_config const*)srv->config_context->data[i];
        plugin_config *s = calloc(1, sizeof(plugin_config));

        s->options = array_init();
        cv[0].destination = s->options;

        p->config_storage[i] = s;

        if (config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
            return HANDLER_ERROR;
        }

        if (s->options->used
            && 0 != mod_vhost_db_dbconf_setup(srv, s->options, &s->vdata)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static void mod_vhost_db_patch_connection (server *srv, connection *con, plugin_data *p)
{
    plugin_config *s = p->config_storage[0];
    PATCH(vdata);

    /* skip the first, the global context */
    for (size_t i = 1; i < srv->config_context->used; ++i) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (size_t j = 0; j < dc->value->used; ++j) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("vhost.mysql"))) {
                PATCH(vdata);
            }
        }
    }
}
#undef PATCH

typedef struct {
    buffer *server_name;
    buffer *document_root;
} vhostdb_entry;

static vhostdb_entry * vhostdb_entry_init (void)
{
    vhostdb_entry *ve = calloc(1, sizeof(*ve));
    ve->server_name = buffer_init();
    ve->document_root = buffer_init();
    return ve;
}

static void vhostdb_entry_free (vhostdb_entry *ve)
{
    buffer_free(ve->server_name);
    buffer_free(ve->document_root);
    free(ve);
}

CONNECTION_FUNC(mod_vhost_db_handle_connection_close) {
    plugin_data *p = p_d;
    vhostdb_entry *ve;

    if ((ve = con->plugin_ctx[p->id])) {
        con->plugin_ctx[p->id] = NULL;
        vhostdb_entry_free(ve);
    }

    UNUSED(srv);
    return HANDLER_GO_ON;
}

static handler_t mod_vhost_db_error_500 (connection *con)
{
    con->http_status = 500; /* Internal Server Error */
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t mod_vhost_db_found (connection *con, vhostdb_entry *ve)
{
    /* fix virtual server and docroot */
    buffer_copy_buffer(con->server_name, ve->server_name);
    buffer_copy_buffer(con->physical.doc_root, ve->document_root);
    return HANDLER_GO_ON;
}

CONNECTION_FUNC(mod_vhost_db_handle_docroot) {
    plugin_data *p = p_d;
    vhostdb_entry *ve;
    buffer *b;
    stat_cache_entry *sce;

    /* no host specified? */
    if (buffer_string_is_empty(con->uri.authority)) return HANDLER_GO_ON;

    mod_vhost_db_patch_connection(srv, con, p);
    if (!p->conf.vdata) return HANDLER_GO_ON;

    /* check if cached this connection */
    ve = con->plugin_ctx[p->id];
    if (ve && buffer_is_equal(ve->server_name, con->uri.authority)) {
        return mod_vhost_db_found(con, ve); /* HANDLER_GO_ON */
    }

    b = p->tmp_buf;
    if (0 != mod_vhost_db_query(p->conf.vdata, con, b)) {
        return mod_vhost_db_error_500(con); /* HANDLER_FINISHED */
    }

    if (buffer_string_is_empty(b)) {
        /* no such virtual host */
        return HANDLER_GO_ON;
    }

    /* sanity check that really is a directory */
    buffer_append_slash(b);
    if (HANDLER_ERROR == stat_cache_get_entry(srv, con, b, &sce)) {
        log_error_write(srv, __FILE__, __LINE__, "sb", strerror(errno), b);
        return mod_vhost_db_error_500(con); /* HANDLER_FINISHED */
    }
    if (!S_ISDIR(sce->st.st_mode)) {
        log_error_write(srv, __FILE__, __LINE__, "sb", "Not a directory", b);
        return mod_vhost_db_error_500(con); /* HANDLER_FINISHED */
    }

    /* cache the data */
    if (!ve) con->plugin_ctx[p->id] = ve = vhostdb_entry_init();
    buffer_copy_buffer(ve->server_name, con->uri.authority);
    buffer_copy_buffer(ve->document_root, b);

    return mod_vhost_db_found(con, ve); /* HANDLER_GO_ON */
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_vhost_mysql_plugin_init (plugin *p);
int mod_vhost_mysql_plugin_init (plugin *p)
{
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = buffer_init_string("vhost_mysql");

    p->init             = mod_vhost_db_init;
    p->cleanup          = mod_vhost_db_cleanup;
    p->set_defaults     = mod_vhost_db_set_defaults;
    p->handle_docroot   = mod_vhost_db_handle_docroot;
    p->connection_reset = mod_vhost_db_handle_connection_close;

    return 0;
}
