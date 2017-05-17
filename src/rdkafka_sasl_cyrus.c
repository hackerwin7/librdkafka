/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2015 Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "rdkafka_int.h"
#include "rdkafka_transport.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_sasl.h"
#include "rdkafka_sasl_int.h"
#include "rdkafka_conf.h"

#ifdef __FreeBSD__
#include <sys/wait.h>  /* For WIF.. */
#endif

#include <sasl/sasl.h>

#define LEN 1024
#define SLEN 512

static mtx_t rd_kafka_sasl_cyrus_kinit_lock;

struct rd_kafka_sasl_state_s {
        sasl_conn_t *conn;
};



/**
 * Handle received frame from broker.
 */
static int rd_kafka_sasl_cyrus_recv (struct rd_kafka_transport_s *rktrans,
                                     const void *buf, size_t size,
                                     char *errstr, size_t errstr_size) {
        rd_kafka_sasl_state_t *state = rktrans->rktrans_sasl.state;
        int r;

        if (rktrans->rktrans_sasl.complete && size == 0)
                goto auth_successful;

        do {
                sasl_interact_t *interact = NULL;
                const char *out;
                unsigned int outlen;

                r = sasl_client_step(state->conn,
                                     size > 0 ? buf : NULL, size,
                                     &interact,
                                     &out, &outlen);

                if (r >= 0) {
                        /* Note: outlen may be 0 here for an empty response */
                        if (rd_kafka_sasl_send(rktrans, out, outlen,
                                               errstr, errstr_size) == -1)
                                return -1;
                }

                if (r == SASL_INTERACT)
                        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "SASL",
                                   "SASL_INTERACT: %lu %s, %s, %s, %p",
                                   interact->id,
                                   interact->challenge,
                                   interact->prompt,
                                   interact->defresult,
                                   interact->result);

        } while (r == SASL_INTERACT);

        if (r == SASL_CONTINUE)
                return 0;  /* Wait for more data from broker */
        else if (r != SASL_OK) {
                rd_snprintf(errstr, errstr_size,
                            "SASL handshake failed (step): %s",
                            sasl_errdetail(state->conn));
                return -1;
        }

        /* Authentication successful */
auth_successful:
        if (rktrans->rktrans_rkb->rkb_rk->rk_conf.debug &
            RD_KAFKA_DBG_SECURITY) {
                const char *user, *mech, *authsrc;

                if (sasl_getprop(state->conn, SASL_USERNAME,
                                 (const void **)&user) != SASL_OK)
                        user = "(unknown)";

                if (sasl_getprop(state->conn, SASL_MECHNAME,
                                 (const void **)&mech) != SASL_OK)
                        mech = "(unknown)";

                if (sasl_getprop(state->conn, SASL_AUTHSOURCE,
                                 (const void **)&authsrc) != SASL_OK)
                        authsrc = "(unknown)";

                rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "SASL",
                           "Authenticated as %s using %s (%s)",
                           user, mech, authsrc);
        }

        rd_kafka_sasl_auth_done(rktrans);

        return 0;
}




static ssize_t render_callback (const char *key, char *buf,
                                size_t size, void *opaque) {
        rd_kafka_broker_t *rkb = opaque;

        if (!strcmp(key, "broker.name")) {
                char *val, *t;
                size_t len;
                rd_kafka_broker_lock(rkb);
                rd_strdupa(&val, rkb->rkb_nodename);
                rd_kafka_broker_unlock(rkb);

                /* Just the broker name, no port */
                if ((t = strchr(val, ':')))
                        len = (size_t)(t-val);
                else
                        len = strlen(val);

                if (buf)
                        memcpy(buf, val, RD_MIN(len, size));

                return len;

        } else {
                rd_kafka_conf_res_t res;
                size_t destsize = size;

                /* Try config lookup. */
                res = rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, key,
                                        buf, &destsize);
                if (res != RD_KAFKA_CONF_OK)
                        return -1;

                /* Dont include \0 in returned size */
                return (destsize > 0 ? destsize-1 : destsize);
        }
}

/**
 * all the args are pre-allocated in default. no memory allocate in this function
 * @param rkb
 * @param use_cmd
 * @param use_keytab
 * @param service_name
 * @param princ_name
 * @param princ_password
 * @param keytab
 * @return
 *//*
static void rd_kafka_krb5_conf_get_retrieve(rd_kafka_broker_t *rkb, int *use_cmd, int *use_keytab, char *service_name,
                                           char *princ_name, char *princ_password, char *keytab) {
        char dest[1024];
        size_t destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.use.cmd", dest, &destsize); // destsize has changed, note it
        *use_cmd = strcmp(dest, "true") == 0 ? 1 : 0;
		destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.use.keytab", dest, &destsize);
        *use_keytab = strcmp(dest, "true") == 0 ? 1 : 0;
		destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.service.name", service_name, &destsize);
		destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.principal", princ_name, &destsize);
		destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.principal.password", princ_password, &destsize);
		destsize = sizeof(dest);
        rd_kafka_conf_get(&rkb->rkb_rk->rk_conf, "sasl.kerberos.keytab", keytab, &destsize);
}*/

static void rd_kafka_krb5_conf_get(rd_kafka_broker_t *rkb, int *use_cmd, int *use_keytab, char *service_name,
                                 char *princ_name, char *princ_password, char *keytab, char * brokername, int *usekrb5conf) {
        rd_kafka_conf_t conf = rkb->rkb_rk->rk_conf;
        *use_cmd = strcmp(conf.sasl.usecmd, "true") == 0 ? 1 : 0;
        *use_keytab = strcmp(conf.sasl.usekeytab, "true") == 0 ? 1 : 0;
        strcpy(service_name, conf.sasl.service_name);
		strcpy(princ_name, conf.sasl.principal);
		strcpy(princ_password, conf.sasl.princ_password);
        strcpy(keytab, conf.sasl.keytab);
        *usekrb5conf = strcmp(conf.sasl.usekrb5conf, "true") == 0 ? 1 : 0;

		/* use the broker node name as the default kerberos service hostname, if specific brokername not set */
		if(!conf.sasl.specific_brokername) {
			char *broker, *t;
			size_t len;
			rd_kafka_broker_lock(rkb);
			rd_strdupa(&broker, rkb->rkb_nodename); // alloca() don't need to free, and it freed when function returns.
			rd_kafka_broker_unlock(rkb);
			if((t = strchr(broker, ':'))) len = (size_t)(t - broker);
			else len = strlen(broker);
			memcpy(brokername, broker, len);
			brokername[len] = '\0';
		} else {
			strcpy(brokername, conf.sasl.specific_brokername);
		}
}

/* kerboers custom profile lib
 * see detail in kerboers sources: profile.h, test_vtable.c prof_int.c*/
#include "krb5/prof_int.h"

static void free_values(void *cbdata, char **values) {
    char **v;
    for(v = values; *v; v++) {
        free(*v);
    }
    free(values);
}

/**
 * dynamic config info
 * @param cbdata
 * @param names
 * @param ret_values
 * @return
 */
static long get_values(void *cbdata, const char *const *names, char ***ret_values) {
    if(names[0] == NULL)
        return PROF_NO_RELATION;
    if(!strcmp(names[0], "libdefaults")) {
        *ret_values = calloc(2, sizeof(*ret_values));
        if(!strcmp(names[1], "default_realm")) {
            (*ret_values)[0] = strdup("BDP.JD.COM");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "dns_lookup_realm") ||
                !strcmp(names[0], "dns_lookup_kdc") ||
                !strcmp(names[0], "rdns")) {
            (*ret_values)[0] = strdup("false");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "ticket_lifetime")) {
            (*ret_values)[0] = strdup("24h");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "renew_lifetime")) {
            (*ret_values)[0] = strdup("7d");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "forwardable")) {
            (*ret_values)[0] = strdup("true");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "kdc_timeout")) {
            (*ret_values)[0] = strdup("10000");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "max_retries")) {
            (*ret_values)[0] = strdup("2");
            (*ret_values)[1] = NULL;
        } else {
            free(*ret_values);
            return PROF_NO_RELATION;
        }
    } else if(!strcmp(names[0], "realms")) {
        if(!strcmp(names[1], "BDP.JD.COM")) {
            *ret_values = calloc(2, sizeof(*ret_values));
            if(!strcmp(names[2], "kdc")) {
                (*ret_values)[0] = strdup("BJHC-JDQ-HUANGHE-7126.hadoop.jd.local");
                (*ret_values)[1] = NULL;
            } else if(!strcmp(names[2], "admin_server")) {
                (*ret_values)[0] = strdup("BJHC-JDQ-HUANGHE-7126.hadoop.jd.local");
                (*ret_values)[1] = NULL;
            } else {
                free(*ret_values);
                return PROF_NO_RELATION;
            }
        } else {
            return PROF_NO_RELATION;
        }
    } else if(!strcmp(names[0], "domain_realm")) {
        *ret_values = calloc(2, sizeof(*ret_values));
        if(!strcmp(names[1], ".hadoop.jd.local")) {
            (*ret_values)[0] = strdup("BDP.JD.COM");
            (*ret_values)[1] = NULL;
        } else if(!strcmp(names[1], "hadoop.jd.local")) {
            (*ret_values)[0] = strdup("BDP.JD.COM");
            (*ret_values)[1] = NULL;
        } else {
            free(*ret_values);
            return PROF_NO_RELATION;
        }
    } else {
        return PROF_NO_RELATION;
    }
    return 0;
}

struct profile_vtable vtable = {
        1,
        get_values,
        free_values,
};

/**
 * load kerberos configuration (dynamic krb5.conf) to context profile
 */
static int rd_kafka_krb5_init_context_custom_profile(krb5_context *context) {
    /* init context profile */
    profile_t profile;
    int cbdata;
    /* init custom profile */
    profile_init_vtable(&vtable, &cbdata, &profile); // !!! note: before krb5-libs 1.12.2, this function is inaccessible to the krb5-libs,
                                                     // even though you link the libkrb5, it still throw the "undefined reference to `profile_init_vtable'"

    krb5_init_context_profile(profile, 0, context);
    profile_release(profile);
    return 0;
}

/**
 * Add a kerberos api block to refresh the ticket
 *
 * Returns 0 on success, not 0 on error
 */
static int rd_kafka_krb5_tgt_refresh_password(rd_kafka_broker_t *rkb, const char * princ_name,
                                              const char * password, const char * service, const char * brokername, int usekrb5conf) {
        krb5_error_code ret = 0;
        krb5_creds creds;
        krb5_principal principal = NULL;
        krb5_context context;
        krb5_ccache ccache = NULL;
        krb5_get_init_creds_opt * options = NULL;
        char service_name[SLEN];
        int stage = 0;

        strcpy(service_name, service);
        strcpy(service_name + strlen(service), "/");
        strcpy(service_name + strlen(service) + 1, brokername);
        service_name[strlen(service) + strlen(brokername) + 1] = '\0';
        memset(&creds, 0, sizeof(creds));
        if(usekrb5conf)
            krb5_init_context(&context);
        else
            rd_kafka_krb5_init_context_custom_profile(&context);

        switch(stage) {
                /* Configure */
                default:
                        stage = 0;
                case 0:
                        if((ret = krb5_cc_default(context, &ccache)))
                                break;
                stage++;
                case 1:
                        if((ret = krb5_parse_name_flags(context, princ_name, 0, &principal)))
                                break;
                stage++;
                case 2:
                        if((ret = krb5_get_init_creds_opt_alloc(context, &options)))
                                break;
                stage++;
                case 3:
                        if((ret = krb5_get_init_creds_opt_set_out_ccache(context, options, ccache)))
                                break;
                stage++;
                /* Connect */
                case 4:
                        if((ret = krb5_get_init_creds_password(context, &creds, principal, password,
                                                        NULL, NULL, 0, service_name, options)))
                                break;
                stage++;
                case 5:
                        if((ret = krb5_verify_init_creds(context, &creds, NULL, NULL, NULL, NULL)))
                                break;
                stage++;
                case 6:
                        if(krb5_cc_switch(context, ccache))
                            break;
                stage++;
        }

        rd_rkb_dbg(rkb, SECURITY, "KRB5REFRESH",
               "stage = %d, error code = %"PRId32"", stage, ret);

        if(options) krb5_get_init_creds_opt_free(context, options);
        if(creds.client == principal) creds.client = 0;
        krb5_free_principal(context, principal);
        krb5_free_cred_contents(context, &creds);
        krb5_cc_close(context, ccache);
        krb5_free_context(context);

        return 0;
}

/**
 * Add a kerberos api block to refresh the ticket
 *
 * Returns 0 on success, not 0 on error
 */
static int rd_kafka_krb5_tgt_refresh_keytab(rd_kafka_broker_t *rkb, const char * princ_name,
                                            const char * keytab_name, const char * service, const char * brokername, int usekrb5conf) {
        krb5_error_code ret = 0;
        krb5_creds creds;
        krb5_principal principal = NULL;
        krb5_context context;
        krb5_ccache ccache = NULL;
        krb5_keytab keytab = 0;
        krb5_get_init_creds_opt * options = NULL;
        char servicename[SLEN];
        int stage = 0;

        strcpy(servicename, service);
        strcpy(servicename + strlen(service), "/");
        strcpy(servicename + strlen(service) + 1, brokername);
        servicename[strlen(service) + strlen(brokername) + 1] = '\0';
        memset(&creds, 0, sizeof(creds));
        if(usekrb5conf)
            krb5_init_context(&context);
        else
            rd_kafka_krb5_init_context_custom_profile(&context);

        switch(stage) {
        /* Configure */
        default:
            stage = 0;
        case 0:
            if((ret = krb5_cc_default(context, &ccache)))
                break;
            stage++;
        case 1:
            if((ret = krb5_parse_name_flags(context, princ_name, 0, &principal)))
                break;
            stage++;
        case 2:
            if((ret = krb5_get_init_creds_opt_alloc(context, &options)))
                break;
            stage++;
        case 3:
            if((ret = krb5_get_init_creds_opt_set_out_ccache(context, options, ccache)))
                break;
            stage++;
        case 4:
            if((ret = krb5_kt_resolve(context, keytab_name, &keytab)))
                break;
            stage++;
            /* Connect */
        case 5:
            if((ret = krb5_get_init_creds_keytab(context, &creds, principal, keytab,
                                                   0, servicename, options)))
                break;
            stage++;
        case 6:
            if((ret = krb5_verify_init_creds(context, &creds, NULL, NULL, NULL, NULL)))
                break;
            stage++;
        case 7:
            if(krb5_cc_switch(context, ccache))
                break;
            stage++;
        }

        rd_rkb_dbg(rkb, SECURITY, "KRB5REFRESH",
               "stage = %d, error code = %"PRId32"", stage, ret);

        if(options) krb5_get_init_creds_opt_free(context, options);
        if(creds.client == principal) creds.client = 0;
        krb5_free_principal(context, principal);
        krb5_free_cred_contents(context, &creds);
        krb5_cc_close(context, ccache);
        krb5_kt_close(context, keytab);
        krb5_free_context(context);

        return 0;
}

/**
 * Execute kinit to refresh ticket.
 *
 * Returns 0 on success, -1 on error.
 *
 * Locality: any
 */
static int rd_kafka_sasl_cyrus_kinit_refresh_cmd(rd_kafka_broker_t *rkb) {
        rd_kafka_t *rk = rkb->rkb_rk;
        int r;
        char *cmd;
        char errstr[128];

        if (!rk->rk_conf.sasl.kinit_cmd ||
            !strstr(rk->rk_conf.sasl.mechanisms, "GSSAPI"))
                return 0; /* kinit not configured */

        /* Build kinit refresh command line using string rendering and config */
        cmd = rd_string_render(rk->rk_conf.sasl.kinit_cmd,
                               errstr, sizeof(errstr),
                               render_callback, rkb);
        if (!cmd) {
                rd_rkb_log(rkb, LOG_ERR, "SASLREFRESH",
                           "Failed to construct kinit command "
                                   "from sasl.kerberos.kinit.cmd template: %s",
                           errstr);
                return -1;
        }

        /* Execute kinit */
        rd_rkb_dbg(rkb, SECURITY, "SASLREFRESH",
                   "Refreshing SASL keys with command: %s", cmd);

        mtx_lock(&rd_kafka_sasl_cyrus_kinit_lock);
        r = system(cmd);
        mtx_unlock(&rd_kafka_sasl_cyrus_kinit_lock);

        if (r == -1) {
                rd_rkb_log(rkb, LOG_ERR, "SASLREFRESH",
                           "SASL key refresh failed: Failed to execute %s",
                           cmd);
                rd_free(cmd);
                return -1;
        } else if (WIFSIGNALED(r)) {
                rd_rkb_log(rkb, LOG_ERR, "SASLREFRESH",
                           "SASL key refresh failed: %s: received signal %d",
                           cmd, WTERMSIG(r));
                rd_free(cmd);
                return -1;
        } else if (WIFEXITED(r) && WEXITSTATUS(r) != 0) {
                rd_rkb_log(rkb, LOG_ERR, "SASLREFRESH",
                           "SASL key refresh failed: %s: exited with code %d",
                           cmd, WEXITSTATUS(r));
                rd_free(cmd);
                return -1;
        }

        rd_free(cmd);

        rd_rkb_dbg(rkb, SECURITY, "SASLREFRESH", "SASL key refreshed");
        return 0;
}

/**
 * Different strategies to refresh the kerberos tgt
 *
 * Locality: any
 */
static int rd_kafka_sasl_cyrus_kinit_refresh (rd_kafka_broker_t *rkb) {

//        //debug
//        int usecmd, usekeytab;
//        char service[SLEN], principal[SLEN], password[SLEN], keytab[LEN];
//        rd_kafka_krb5_conf_get_retrieve(rkb, &usecmd, &usekeytab, service, principal, password, keytab);
//        rd_rkb_log(rkb, LOG_INFO, "KRB5CONFIG",
//                "use cmd = %d, use keytab = %d, service = %s, principal = %s, password = %s, keytab = %s", usecmd, usekeytab, service, principal, password, keytab);
//        rd_kafka_krb5_conf_get(rkb, &usecmd, &usekeytab, service, principal, password, keytab);
//        rd_rkb_log(rkb, LOG_INFO, "KRB5CONFIG",
//                   "use cmd = %d, use keytab = %d, service = %s, principal = %s, password = %s, keytab = %s", usecmd, usekeytab, service, principal, password, keytab);


        /* configure the kerberos tgt refresh strategies/mode */
        /* mode
         * 0:cmd with keytab,
         * 1:no-cmd with keytab,
         * 2:no-cmd with password.
         * */
        int mode = -1;
        int usecmd, usekeytab, usekrb5conf;
        char service[SLEN], principal[SLEN], password[SLEN], keytab[LEN], brokername[SLEN];
        rd_kafka_krb5_conf_get(rkb, &usecmd, &usekeytab, service, principal, password, keytab, brokername, &usekrb5conf);
        if(!usecmd) {
                if(!usekeytab) mode = 2;
                else mode = 1;
        } else {
                mode = 0;
        }

        rd_rkb_dbg(rkb, SECURITY, "KRB5CONFIG",
                   "use cmd = %d, use keytab = %d, service = %s, principal = %s, password = %s, keytab = %s, broker = %s, use krb5.conf = %d",
                   usecmd, usekeytab, service, principal, password, keytab, brokername, usekrb5conf);

        switch (mode) {
                case 0:
                        rd_kafka_sasl_cyrus_kinit_refresh_cmd(rkb);
                        break;
                case 1:
                        mtx_lock(&rd_kafka_sasl_cyrus_kinit_lock);
                        rd_kafka_krb5_tgt_refresh_keytab(rkb, principal, keytab, service, brokername, usekrb5conf);
                        mtx_unlock(&rd_kafka_sasl_cyrus_kinit_lock);
                        break;
                case 2:
                        mtx_lock(&rd_kafka_sasl_cyrus_kinit_lock);
                        rd_kafka_krb5_tgt_refresh_password(rkb, principal, password, service, brokername, usekrb5conf);
                        mtx_unlock(&rd_kafka_sasl_cyrus_kinit_lock);
                        break;
        }

        rd_rkb_dbg(rkb, SECURITY, "SASLREFRESH", "SASL key refreshed");
        return 0;
}


/**
 * Refresh timer callback
 *
 * Locality: kafka main thread
 */
static void rd_kafka_sasl_cyrus_kinit_refresh_tmr_cb (rd_kafka_timers_t *rkts,
                                                      void *arg) {
        rd_kafka_broker_t *rkb = arg;

        rd_kafka_sasl_cyrus_kinit_refresh(rkb);
}



/**
 *
 * libsasl callbacks
 *
 */
static RD_UNUSED int
rd_kafka_sasl_cyrus_cb_getopt (void *context, const char *plugin_name,
                         const char *option,
                         const char **result, unsigned *len) {
        rd_kafka_transport_t *rktrans = context;

        if (!strcmp(option, "client_mech_list"))
                *result = "GSSAPI";
        if (!strcmp(option, "canon_user_plugin"))
                *result = "INTERNAL";

        if (*result && len)
                *len = strlen(*result);

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_GETOPT: plugin %s, option %s: returning %s",
                   plugin_name, option, *result);

        return SASL_OK;
}

static int rd_kafka_sasl_cyrus_cb_log (void *context, int level, const char *message){
        rd_kafka_transport_t *rktrans = context;

        if (level >= LOG_DEBUG)
                rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                           "%s", message);
        else
                rd_rkb_log(rktrans->rktrans_rkb, level, "LIBSASL",
                           "%s", message);
        return SASL_OK;
}


static int rd_kafka_sasl_cyrus_cb_getsimple (void *context, int id,
                                       const char **result, unsigned *len) {
        rd_kafka_transport_t *rktrans = context;

        switch (id)
        {
        case SASL_CB_USER:
        case SASL_CB_AUTHNAME:
                *result = rktrans->rktrans_rkb->rkb_rk->rk_conf.sasl.username;
                break;

        default:
                *result = NULL;
                break;
        }

        if (len)
                *len = *result ? strlen(*result) : 0;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_GETSIMPLE: id 0x%x: returning %s", id, *result);

        return *result ? SASL_OK : SASL_FAIL;
}


static int rd_kafka_sasl_cyrus_cb_getsecret (sasl_conn_t *conn, void *context,
                                       int id, sasl_secret_t **psecret) {
        rd_kafka_transport_t *rktrans = context;
        const char *password;

        password = rktrans->rktrans_rkb->rkb_rk->rk_conf.sasl.password;

        if (!password) {
                *psecret = NULL;
        } else {
                size_t passlen = strlen(password);
                *psecret = rd_realloc(*psecret, sizeof(**psecret) + passlen);
                (*psecret)->len = passlen;
                memcpy((*psecret)->data, password, passlen);
        }

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_GETSECRET: id 0x%x: returning %s",
                   id, *psecret ? "(hidden)":"NULL");

        return SASL_OK;
}

static int rd_kafka_sasl_cyrus_cb_chalprompt (void *context, int id,
                                        const char *challenge,
                                        const char *prompt,
                                        const char *defres,
                                        const char **result, unsigned *len) {
        rd_kafka_transport_t *rktrans = context;

        *result = "min_chalprompt";
        *len = strlen(*result);

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_CHALPROMPT: id 0x%x, challenge %s, prompt %s, "
                   "default %s: returning %s",
                   id, challenge, prompt, defres, *result);

        return SASL_OK;
}

static int rd_kafka_sasl_cyrus_cb_getrealm (void *context, int id,
                                      const char **availrealms,
                                      const char **result) {
        rd_kafka_transport_t *rktrans = context;

        *result = *availrealms;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_GETREALM: id 0x%x: returning %s", id, *result);

        return SASL_OK;
}


static RD_UNUSED int
rd_kafka_sasl_cyrus_cb_canon (sasl_conn_t *conn,
                              void *context,
                              const char *in, unsigned inlen,
                              unsigned flags,
                              const char *user_realm,
                              char *out, unsigned out_max,
                              unsigned *out_len) {
        rd_kafka_transport_t *rktrans = context;

        if (strstr(rktrans->rktrans_rkb->rkb_rk->rk_conf.
                   sasl.mechanisms, "GSSAPI")) {
                *out_len = rd_snprintf(out, out_max, "%s",
                                       rktrans->rktrans_rkb->rkb_rk->
                                       rk_conf.sasl.principal);
        } else if (!strcmp(rktrans->rktrans_rkb->rkb_rk->rk_conf.
                           sasl.mechanisms, "PLAIN")) {
                *out_len = rd_snprintf(out, out_max, "%.*s", inlen, in);
        } else
                out = NULL;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "LIBSASL",
                   "CB_CANON: flags 0x%x, \"%.*s\" @ \"%s\": returning \"%.*s\"",
                   flags, (int)inlen, in, user_realm, (int)(*out_len), out);

        return out ? SASL_OK : SASL_FAIL;
}


static void rd_kafka_sasl_cyrus_close (struct rd_kafka_transport_s *rktrans) {
        if (rktrans->rktrans_sasl.state->conn)
                sasl_dispose(&rktrans->rktrans_sasl.state->conn);
        rd_free(rktrans->rktrans_sasl.state);
}


/**
 * Initialize and start SASL authentication.
 *
 * Returns 0 on successful init and -1 on error.
 *
 * Locality: broker thread
 */
int rd_kafka_sasl_cyrus_client_new (rd_kafka_transport_t *rktrans,
                                    const char *hostname,
                                    char *errstr, size_t errstr_size) {
        int r;
        rd_kafka_sasl_state_t *state;
        rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
        rd_kafka_t *rk = rkb->rkb_rk;
        sasl_callback_t callbacks[16] = {
                // { SASL_CB_GETOPT, (void *)rd_kafka_sasl_cyrus_cb_getopt, rktrans },
                { SASL_CB_LOG, (void *)rd_kafka_sasl_cyrus_cb_log, rktrans },
                { SASL_CB_AUTHNAME, (void *)rd_kafka_sasl_cyrus_cb_getsimple, rktrans },
                { SASL_CB_PASS, (void *)rd_kafka_sasl_cyrus_cb_getsecret, rktrans },
                { SASL_CB_ECHOPROMPT, (void *)rd_kafka_sasl_cyrus_cb_chalprompt, rktrans },
                { SASL_CB_GETREALM, (void *)rd_kafka_sasl_cyrus_cb_getrealm, rktrans },
                { SASL_CB_CANON_USER, (void *)rd_kafka_sasl_cyrus_cb_canon, rktrans },
                { SASL_CB_LIST_END }
        };

        state = rd_calloc(1, sizeof(*state));
        rktrans->rktrans_sasl.state = state;
        rktrans->rktrans_sasl.recv = rd_kafka_sasl_cyrus_recv;
        rktrans->rktrans_sasl.close = rd_kafka_sasl_cyrus_close;

        /* SASL_CB_USER is needed for PLAIN but breaks GSSAPI */
        if (!strcmp(rk->rk_conf.sasl.mechanisms, "PLAIN")) {
                int endidx;
                /* Find end of callbacks array */
                for (endidx = 0 ;
                     callbacks[endidx].id != SASL_CB_LIST_END ; endidx++)
                        ;

                callbacks[endidx].id = SASL_CB_USER;
                callbacks[endidx].proc = (void *)rd_kafka_sasl_cyrus_cb_getsimple;
                callbacks[endidx].context = rktrans;
                endidx++;
                callbacks[endidx].id = SASL_CB_LIST_END;
        }

        /* Acquire or refresh ticket if kinit is configured */
        rd_kafka_sasl_cyrus_kinit_refresh(rkb);

        r = sasl_client_new(rk->rk_conf.sasl.service_name, hostname,
                            NULL, NULL, /* no local & remote IP checks */
                            callbacks, 0, &state->conn);
        if (r != SASL_OK) {
                rd_snprintf(errstr, errstr_size, "%s",
                            sasl_errstring(r, NULL, NULL));
                return -1;
        }

        if (rk->rk_conf.debug & RD_KAFKA_DBG_SECURITY) {
                const char *avail_mechs;
                sasl_listmech(state->conn, NULL, NULL, " ", NULL,
                              &avail_mechs, NULL, NULL);
                rd_rkb_dbg(rkb, SECURITY, "SASL",
                           "My supported SASL mechanisms: %s", avail_mechs);
        }

        do {
                const char *out;
                unsigned int outlen;
                const char *mech = NULL;

                r = sasl_client_start(state->conn,
                                      rk->rk_conf.sasl.mechanisms,
                                      NULL, &out, &outlen, &mech);

                if (r >= 0)
                        if (rd_kafka_sasl_send(rktrans, out, outlen,
                                               errstr, errstr_size))
                                return -1;
        } while (r == SASL_INTERACT);

        if (r == SASL_OK) {
                /* PLAIN is appearantly done here, but we still need to make sure
                 * the PLAIN frame is sent and we get a response back (but we must
                 * not pass the response to libsasl or it will fail). */
                rktrans->rktrans_sasl.complete = 1;
                return 0;

        } else if (r != SASL_CONTINUE) {
                rd_snprintf(errstr, errstr_size,
                            "SASL handshake failed (start (%d)): %s",
                            r, sasl_errdetail(state->conn));
                return -1;
        }

        return 0;
}







/**
 * Per handle SASL term.
 *
 * Locality: broker thread
 */
void rd_kafka_broker_sasl_cyrus_term (rd_kafka_broker_t *rkb) {
        rd_kafka_t *rk = rkb->rkb_rk;

        if (!rk->rk_conf.sasl.kinit_cmd)
                return;

        rd_kafka_timer_stop(&rk->rk_timers, &rkb->rkb_sasl_kinit_refresh_tmr,1);
}

/**
 * Broker SASL init.
 *
 * Locality: broker thread
 */
void rd_kafka_broker_sasl_cyrus_init (rd_kafka_broker_t *rkb) {
        rd_kafka_t *rk = rkb->rkb_rk;

        if (!rk->rk_conf.sasl.kinit_cmd ||
            !strstr(rk->rk_conf.sasl.mechanisms, "GSSAPI"))
                return; /* kinit not configured, no need to start timer */

        rd_kafka_timer_start(&rk->rk_timers, &rkb->rkb_sasl_kinit_refresh_tmr,
                             rk->rk_conf.sasl.relogin_min_time * 1000ll,
                             rd_kafka_sasl_cyrus_kinit_refresh_tmr_cb, rkb);
}



int rd_kafka_sasl_cyrus_conf_validate (rd_kafka_t *rk,
                                       char *errstr, size_t errstr_size) {

        if (strcmp(rk->rk_conf.sasl.mechanisms, "GSSAPI"))
                return 0;

        if (rk->rk_conf.sasl.kinit_cmd) {
                rd_kafka_broker_t rkb;
                char *cmd;
                char tmperr[128];

                memset(&rkb, 0, sizeof(rkb));
                strcpy(rkb.rkb_nodename, "ATestBroker:9092");
                rkb.rkb_rk = rk;
                mtx_init(&rkb.rkb_lock, mtx_plain);

                cmd = rd_string_render(rk->rk_conf.sasl.kinit_cmd,
                                       tmperr, sizeof(tmperr),
                                       render_callback, &rkb);

                mtx_destroy(&rkb.rkb_lock);

                if (!cmd) {
                        rd_snprintf(errstr, errstr_size,
                                    "Invalid sasl.kerberos.kinit.cmd value: %s",
                                    tmperr);
                        return -1;
                }

                rd_free(cmd);
        }

        return 0;
}


/**
 * Global SASL termination.
 */
void rd_kafka_sasl_cyrus_global_term (void) {
        /* NOTE: Should not be called since the application may be using SASL too*/
        /* sasl_done(); */
        mtx_destroy(&rd_kafka_sasl_cyrus_kinit_lock);
}


/**
 * Global SASL init, called once per runtime.
 */
int rd_kafka_sasl_cyrus_global_init (void) {
        int r;

        mtx_init(&rd_kafka_sasl_cyrus_kinit_lock, mtx_plain);

        r = sasl_client_init(NULL);
        if (r != SASL_OK) {
                fprintf(stderr, "librdkafka: sasl_client_init() failed: %s\n",
                        sasl_errstring(r, NULL, NULL));
                return -1;
        }

        return 0;
}

