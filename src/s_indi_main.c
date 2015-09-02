/*
 * tel-plugin-indicator
 *
 * Copyright (c) 2014 Samsung Electronics Co. Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>
#include <gio/gio.h>

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <storage.h>
#include <co_ps.h>
#include <co_context.h>
#include <co_sim.h>
#include <co_network.h>
#include <co_call.h>

#include "s_indi_main.h"
#include "s_indi_util.h"
#include "s_indi_log.h"

#define S_INDI_UPDATE_INTERVAL		1
#define S_INDI_PROC_FILE			"/proc/net/dev"

#define S_INDI_VCONF_STORAGE_NAME		"vconf"

#define S_INDI_ALLOC_USER_DATA(data, plugin, cp) \
	do { \
		data = s_indi_malloc0(sizeof(__s_indi_cb_user_data)); \
		if (data == NULL) { \
			err("Memory allocation failed!!"); \
			s_indi_free(cp); \
			return FALSE; \
		} \
		data->indi_plugin = plugin; \
		data->cp_name = cp; \
	} while (0)

#define S_INDI_FREE_USER_DATA(data) \
	do { \
		s_indi_free(data->cp_name); \
		s_indi_free(data); \
	} while (0)

typedef struct {
	TcorePlugin *indi_plugin;
	gchar *cp_name;
} __s_indi_cb_user_data;

typedef struct {
	GHashTable *state_info; /* HashTable of s_indi_cp_state_info_type with key = cp_name */

	GHashTable *vconf_info; /* Mapping of enum tcore_storage_key to cp_name */
} s_indi_private_info;

/***************** HOOKS *****************/
static enum tcore_hook_return s_indi_on_hook_modem_plugin_removed(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);
static enum tcore_hook_return s_indi_on_hook_modem_plugin_added(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);
static enum tcore_hook_return s_indi_on_hook_voice_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);
static enum tcore_hook_return s_indi_on_hook_net_register(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);
static enum tcore_hook_return s_indi_on_hook_ps_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);
static enum tcore_hook_return s_indi_on_hook_modem_power(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data);

/***************** VCONF Callbacks *****************/
static void s_indi_storage_key_callback(enum tcore_storage_key key, void *value, void *user_data);

/***************** Utilities: GDestroyNotifications *****************/
static void __s_indi_state_info_value_destroy_notification(gpointer data);
static void __s_indi_dev_info_value_destroy_notification(gpointer data);

/***************** Utilities: Indicator Plugin *****************/
static inline s_indi_private_info *__s_indi_get_priv_info(TcorePlugin *plugin);
static gboolean __s_indi_start_updater(TcorePlugin *indi_plugin, gchar *cp_name);
static gboolean __s_indi_update_callback(__s_indi_cb_user_data *data);
static void __s_indi_refresh_modems(TcorePlugin *indi_plugin);
static s_indi_cp_state_info_type *__s_indi_alloc_state_info(CoreObject *co_ps);
static s_indi_dev_state_info_type *__s_indi_alloc_device_state(CoreObject *ps_context, s_indi_cp_state_info_type *parent);
static CoreObject *__s_indi_fetch_ps_co(TcorePlugin *plugin);

static void __s_indi_add_modem_plugin(TcorePlugin *indi_plugin, TcorePlugin *modem_plugin);
static void __s_indi_remove_modem_plugin(TcorePlugin *indi_plugin, TcorePlugin *modem_plugin);
static void __s_indi_register_vconf_key(enum tcore_storage_key key, TcorePlugin *indi_plugin, const char *cp_name);
static void __s_indi_unregister_vconf_key(enum tcore_storage_key key, TcorePlugin *indi_plugin, const char *cp_name);
static gboolean __s_indi_handle_voice_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, const char *cp_name,
	s_indi_cp_state_info_type *state_info);

void __s_indi_register_vconf_key(enum tcore_storage_key key, TcorePlugin *indi_plugin, const char *cp_name)
{
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	Storage *strg_vconf = tcore_server_find_storage(tcore_plugin_ref_server(indi_plugin), S_INDI_VCONF_STORAGE_NAME);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}
	s_indi_assert(NULL != strg_vconf);

	/** NULL cp_name: subscription independent vconf key */
	if (tcore_storage_set_key_callback(strg_vconf, key, s_indi_storage_key_callback, indi_plugin)
			&& (NULL != cp_name))
		g_hash_table_insert(priv_info->vconf_info, GUINT_TO_POINTER(key), s_indi_strdup(cp_name));
}

void __s_indi_unregister_vconf_key(enum tcore_storage_key key, TcorePlugin *indi_plugin, const char *cp_name)
{
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	Storage *strg_vconf = tcore_server_find_storage(tcore_plugin_ref_server(indi_plugin), S_INDI_VCONF_STORAGE_NAME);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}
	s_indi_assert(NULL != strg_vconf);

	/** NULL cp_name: subscription independent vconf key */
	if (tcore_storage_remove_key_callback(strg_vconf, key, s_indi_storage_key_callback)
		&& (NULL != cp_name))
		g_hash_table_remove(priv_info->vconf_info, GUINT_TO_POINTER(key));
}

void __s_indi_add_modem_plugin(TcorePlugin *indi_plugin, TcorePlugin *modem_plugin)
{
	gchar *cp_name = NULL;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}

	/** @todo: It may be possible to use cp_name without duping as well */
	cp_name = s_indi_strdup(tcore_server_get_cp_name_by_plugin(modem_plugin));
	s_indi_assert(NULL != cp_name);
	s_indi_log_ex(cp_name, "Added");

	/** @todo: Check if key-value replacement is the intended behavior */
	g_hash_table_insert(priv_info->state_info, cp_name, __s_indi_alloc_state_info(__s_indi_fetch_ps_co(modem_plugin)));
}

void __s_indi_remove_modem_plugin(TcorePlugin *indi_plugin, TcorePlugin *modem_plugin)
{
	const char *cp_name = NULL;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}
	s_indi_assert(NULL != priv_info->state_info);

	cp_name = tcore_server_get_cp_name_by_plugin(modem_plugin);
	s_indi_assert(NULL != cp_name);

	if (g_hash_table_remove(priv_info->state_info, cp_name))
		s_indi_log_ex(cp_name, "Removed");
}

CoreObject *__s_indi_fetch_ps_co(TcorePlugin *plugin)
{
	CoreObject *co_ps = NULL;
	GSList *co_list = tcore_plugin_get_core_objects_bytype(plugin, CORE_OBJECT_TYPE_PS);
	s_indi_assert(co_list != NULL);
	s_indi_assert(g_slist_length(co_list) == S_INDI_ONE);

	co_ps = g_slist_nth_data(co_list, S_INDI_ZERO);
	s_indi_assert(co_ps != NULL);
	g_slist_free(co_list);

	return co_ps;
}

s_indi_cp_state_info_type *__s_indi_alloc_state_info(CoreObject *co_ps)
{
	s_indi_cp_state_info_type *state_info = s_indi_malloc0(sizeof(s_indi_cp_state_info_type));
	if (!state_info) {
		err("Memory allocation failed!!");
		return NULL;
	}
	state_info->co_ps = co_ps;
	state_info->ps_state = S_INDI_CELLULAR_UNKNOWN;
	state_info->cp_trans_state = S_INDI_TRANSFER_UNKNOWN;
	state_info->dormant_info.lcd_state = S_INDI_LCD_UNKNOWN;
	state_info->rx_total = S_INDI_ZERO;
	state_info->tx_total = S_INDI_ZERO;
	state_info->dormant_info.parent = state_info;

	/* tcore_context_get_ipv4_devname uses glib allocator so key should be freed using g_free() */
	state_info->device_info = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, __s_indi_dev_info_value_destroy_notification);
	return state_info;
}

s_indi_dev_state_info_type *__s_indi_alloc_device_state(CoreObject *ps_context, s_indi_cp_state_info_type *parent)
{
	s_indi_dev_state_info_type *dev_state = s_indi_malloc0(sizeof(s_indi_dev_state_info_type));
	if (dev_state == NULL) {
		err("Memory allocation failed!!");
		return NULL;
	}

	dev_state->ps_context = ps_context;
	dev_state->parent = parent;
	return dev_state;
}

s_indi_private_info *__s_indi_get_priv_info(TcorePlugin *plugin)
{
	s_indi_private_info *priv_info = tcore_plugin_ref_user_data(plugin);
	s_indi_assert(NULL != priv_info);
	return priv_info;
}

gboolean __s_indi_start_updater(TcorePlugin *indi_plugin, gchar *cp_name)
{
	__s_indi_cb_user_data *cb_data = NULL;
	s_indi_cp_state_info_type *state_info = NULL;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return FALSE;
	}

	if ((state_info = g_hash_table_lookup(priv_info->state_info, cp_name)) == NULL) {
		warn("CP [%s] Not Present", cp_name);
		s_indi_free(cp_name);
		return FALSE;
	}

	if (state_info->src != NULL) {
		dbg("Another one is in progress");
		s_indi_free(cp_name);
		return FALSE;
	}

	S_INDI_ALLOC_USER_DATA(cb_data, indi_plugin, cp_name);

	dbg("indicator is starting");
	state_info->src = g_timeout_source_new_seconds(S_INDI_UPDATE_INTERVAL);
	g_source_set_callback(state_info->src, (GSourceFunc)__s_indi_update_callback, cb_data, NULL);
	g_source_set_priority(state_info->src, G_PRIORITY_HIGH);
	g_source_attach(state_info->src, NULL);
	g_source_unref(state_info->src);
	return TRUE;
}

gboolean __s_indi_update_callback(__s_indi_cb_user_data *data)
{
#define INDICATOR_BUFF_SIZE 4096
	gchar buff[INDICATOR_BUFF_SIZE];
	s_indi_cp_state_info_type *state_info = NULL;
	s_indi_dev_state_info_type *dev_state = NULL;
	TcorePlugin *indi_plugin = data->indi_plugin;
	const char *cp_name = data->cp_name;
	unsigned int modem_id;
	FILE *pf = NULL;
	gchar *rv = NULL;
	unsigned long long rx_curr_total = S_INDI_ZERO, tx_curr_total = S_INDI_ZERO, rx_prev_total = S_INDI_ZERO, tx_prev_total = S_INDI_ZERO;
	unsigned long long rx_changes_total = S_INDI_ZERO, tx_changes_total = S_INDI_ZERO;
	s_indi_transfer_state cp_state = S_INDI_TRANSFER_NORMAL; /* Assume no activity */
	enum tcore_storage_key key_last_rcv, key_last_snt, key_total_rcv, key_total_snt, key_service_state;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	Storage *strg_vconf = NULL;

	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return G_SOURCE_REMOVE;
	}

	/* VCONF Mapper */
	if (s_indi_str_has_suffix(cp_name, "0")) {
		key_last_rcv = STORAGE_KEY_CELLULAR_PKT_LAST_RCV;
		key_last_snt = STORAGE_KEY_CELLULAR_PKT_LAST_SNT;
		key_total_rcv = STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV;
		key_total_snt = STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT;
		key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE;
		modem_id = MODEM_ID_PRIMARY;
	} else if (s_indi_str_has_suffix(cp_name, "1")) {
		key_last_rcv = STORAGE_KEY_CELLULAR_PKT_LAST_RCV2;
		key_last_snt = STORAGE_KEY_CELLULAR_PKT_LAST_SNT2;
		key_total_rcv = STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV2;
		key_total_snt = STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT2;
		key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE2;
		modem_id = MODEM_ID_SECONDARY;
	} else {
		err("Unhandled CP Name %s", cp_name);
		s_indi_assert_not_reached();
		S_INDI_FREE_USER_DATA(data);
		return G_SOURCE_REMOVE;
	}

	/* Check CP Name presence */
	if ((state_info = g_hash_table_lookup(priv_info->state_info, cp_name)) == NULL) {
		warn("%s CP is not present", cp_name);
		goto EXIT;
	}

	/* Check dev_state presence */
	if (g_hash_table_size(state_info->device_info) == S_INDI_ZERO) {
		msg("Nothing to update, aborting timer");
		goto EXIT;
	}

	/** @todo: Check if needs to be read atomically */
	pf = fopen(S_INDI_PROC_FILE, "r");
	if (pf == NULL) {
		err("indicator fail to open file(%s), errno(%d)", S_INDI_PROC_FILE, errno);
		goto EXIT;
	}

	/* Skip first line */
	rv = fgets(buff, sizeof(buff), pf);
	if (!rv) {
		err("fail to read file or reach EOF, plz check %s", S_INDI_PROC_FILE);
		goto EXIT;
	}

	/* Skip second line */
	rv = fgets(buff, sizeof(buff), pf);
	if (!rv) {
		err("fail to read file or reach EOF, plz check %s", S_INDI_PROC_FILE);
		goto EXIT;
	}

	/* Update all devices of state_info */
	while (fgets(buff, sizeof(buff), pf)) {
		gchar *ifname = buff, *entry = NULL;

		/* Skip whitespaces */
		while (*ifname == ' ')
			ifname++;

		/* Terminate to read ifname */
		entry = strrchr(ifname, ':');
		if (entry == NULL)
			goto EXIT;
		*entry++ = '\0';

		/* Read device_info */
		/* Takes care of the fix: Fix the PLM p131003-03182. Sha-ID: 65544f0be8e60ae3f964921755a1e83fa8e71441*/
		if ((dev_state = g_hash_table_lookup(state_info->device_info, ifname)) != NULL) {
			gint result = S_INDI_ZERO;
			unsigned long long rx_pkt = S_INDI_ZERO, tx_pkt = S_INDI_ZERO;
			/************************************************************************
			Sample Input of S_INDI_PROC_FILE
			************************************************************************
			Inter-|   Receive                                                |  Transmit
			 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
			    lo: 114955545   88409    0    0    0     0          0         0 114955545   88409    0    0    0     0       0          0
			  eth0: 2714004148 6475059    0    0    0     0          0         0 72595891 8726308    0    0    0     0       0          0
			************************************************************************/
			s_indi_log_v("Reading stats of interface %s", ifname);
			result = sscanf(entry, "%llu %*s %*s %*s %*s %*s %*s %*s %llu %*s %*s %*s %*s %*s %*s %*s", &rx_pkt, &tx_pkt);
			if (result <= S_INDI_ZERO) {
				err("stats fail to get proc field => %d", result);
				goto EXIT; /** @todo: REMOVE or CONTINUE ? */
			}

			/* Save per device */
			dev_state->prev_rx = dev_state->curr_rx;
			dev_state->prev_tx = dev_state->curr_tx;
			dev_state->curr_rx = rx_pkt;
			dev_state->curr_tx = tx_pkt;

			/* Compute CP totals */
			rx_curr_total += rx_pkt;
			tx_curr_total += tx_pkt;
			rx_prev_total += dev_state->prev_rx;
			tx_prev_total += dev_state->prev_tx;
		}
	}

	rx_changes_total = rx_curr_total - rx_prev_total;
	tx_changes_total = tx_curr_total - tx_prev_total;

	if (rx_changes_total)
		cp_state |= S_INDI_TRANSFER_RX;

	if (tx_changes_total)
		cp_state |= S_INDI_TRANSFER_TX;

	if (cp_state > 0)
		s_indi_log_txrx(modem_id, "Transfer State:[%d] RX: [%llu / %llu] TX: [%llu / %llu]",
			cp_state, rx_changes_total, rx_curr_total, tx_changes_total, tx_curr_total);

	if (state_info->dormant_info.lcd_state < S_INDI_LCD_OFF) {
		if (state_info->cp_trans_state != cp_state) { /* New Transfer State */
			strg_vconf = tcore_server_find_storage(tcore_plugin_ref_server(indi_plugin), S_INDI_VCONF_STORAGE_NAME);
			s_indi_assert(NULL != strg_vconf);

			state_info->cp_trans_state = cp_state;
			tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, cp_state);
			if (cp_state != S_INDI_TRANSFER_NORMAL) { /* Data activity */
				/** @todo: VCONF needs upgrade to support llu */
				tcore_storage_set_int(strg_vconf, key_last_rcv, (int)(rx_curr_total/1000ULL));
				tcore_storage_set_int(strg_vconf, key_last_snt, (int)(tx_curr_total/1000ULL));

				s_indi_log_txrx(modem_id, "VCONF LAST- RX: [%d] TX: [%d]", (int)(rx_curr_total/1000ULL), (int)(tx_curr_total/1000ULL));
			}
		}
	}

	fclose(pf);
	return G_SOURCE_CONTINUE; /* Revisit after S_INDI_UPDATE_INTERVAL */

EXIT:
	dbg("indicator is stopped");
	if (pf) fclose(pf);

	strg_vconf = tcore_server_find_storage(tcore_plugin_ref_server(indi_plugin), S_INDI_VCONF_STORAGE_NAME);
	s_indi_assert(NULL != strg_vconf);

	/* Update PS Call and indicator states */
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, S_INDI_TRANSFER_NORMAL);
	tcore_storage_set_int(strg_vconf, key_service_state, S_INDI_CELLULAR_OFF);
	dbg("PS Call status (%s) - [DISCONNECTED]", cp_name);

	if (state_info) {
		state_info->src = NULL;
		state_info->cp_trans_state = S_INDI_TRANSFER_NORMAL;
		state_info->ps_state = S_INDI_CELLULAR_OFF;

		/* Update total VCONF before dying updator */
		tcore_storage_set_int(strg_vconf, key_total_rcv, tcore_storage_get_int(strg_vconf, key_total_rcv) + state_info->rx_total);
		tcore_storage_set_int(strg_vconf, key_total_snt, tcore_storage_get_int(strg_vconf, key_total_snt) + state_info->tx_total);

		/* After updating total vconf key, last vconf key needs to be reset */
		tcore_storage_set_int(strg_vconf, key_last_rcv, 0);
		tcore_storage_set_int(strg_vconf, key_last_snt, 0);

		/** @todo: VCONF needs upgrade to support llu */
		s_indi_log_txrx(modem_id, "VCONF TOTAL- RX: [%d] TX: [%d]",
			tcore_storage_get_int(strg_vconf, key_total_rcv), tcore_storage_get_int(strg_vconf, key_total_snt));
		state_info->rx_total = S_INDI_ZERO;
		state_info->tx_total = S_INDI_ZERO;
	}

	S_INDI_FREE_USER_DATA(data);
	return G_SOURCE_REMOVE;
}

void __s_indi_state_info_value_destroy_notification(gpointer data)
{
	s_indi_cp_state_info_type *state_info = data;
	const char *cp_name = NULL;
	Storage *strg_vconf = NULL;
	enum tcore_storage_key key_last_rcv, key_last_snt, key_total_rcv, key_total_snt;
	unsigned int modem_id;
	s_indi_assert(NULL != state_info);
	s_indi_assert(NULL != state_info->co_ps);

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(state_info->co_ps));
	s_indi_assert(NULL != cp_name);
	dbg("CP Name: [%s]", cp_name);

	/* VCONF Mapper */
	if (s_indi_str_has_suffix(cp_name, "0")) {
		key_last_rcv = STORAGE_KEY_CELLULAR_PKT_LAST_RCV;
		key_last_snt = STORAGE_KEY_CELLULAR_PKT_LAST_SNT;
		key_total_rcv = STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV;
		key_total_snt = STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT;
		modem_id = MODEM_ID_PRIMARY;
	} else if (s_indi_str_has_suffix(cp_name, "1")) {
		key_last_rcv = STORAGE_KEY_CELLULAR_PKT_LAST_RCV2;
		key_last_snt = STORAGE_KEY_CELLULAR_PKT_LAST_SNT2;
		key_total_rcv = STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV2;
		key_total_snt = STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT2;
		modem_id = MODEM_ID_SECONDARY;
	} else {
		err("Unhandled CP Name %s", cp_name);
		s_indi_assert_not_reached();
		goto OUT;
	}

	/* Free device nodes */
	g_hash_table_destroy(state_info->device_info);
	strg_vconf = tcore_server_find_storage(tcore_plugin_ref_server(tcore_object_ref_plugin(state_info->co_ps)), S_INDI_VCONF_STORAGE_NAME);
	s_indi_assert(NULL != strg_vconf);

	/* Update VCONF before dying */
	tcore_storage_set_int(strg_vconf, key_total_rcv, tcore_storage_get_int(strg_vconf, key_total_rcv) + state_info->rx_total);
	tcore_storage_set_int(strg_vconf, key_total_snt, tcore_storage_get_int(strg_vconf, key_total_snt) + state_info->tx_total);

	/* After updating total vconf key, last vconf key needs to be reset */
	tcore_storage_set_int(strg_vconf, key_last_rcv, 0);
	tcore_storage_set_int(strg_vconf, key_last_snt, 0);

	s_indi_log_txrx(modem_id, "VCONF TOTAL -RX: [%d] TX: [%d]",
			tcore_storage_get_int(strg_vconf, key_total_rcv), tcore_storage_get_int(strg_vconf, key_total_snt));

OUT:
	s_indi_free(data);
}

void __s_indi_dev_info_value_destroy_notification(gpointer data)
{
	s_indi_dev_state_info_type *dev_state = data;
	s_indi_cp_state_info_type *state_info = NULL;
	s_indi_assert(NULL != dev_state);
	state_info = dev_state->parent;
	s_indi_assert(NULL != state_info);

	/* Update parent before dying */
	state_info->rx_total += dev_state->curr_rx/1000ULL;
	state_info->tx_total += dev_state->curr_tx/1000ULL;

	dbg("DYING after contributing [RX: %llu][TX: %llu] OUT OF [RX: %llu][TX: %llu]",
		dev_state->curr_rx/1000ULL, dev_state->curr_tx/1000ULL,
		state_info->rx_total, state_info->tx_total);

	s_indi_free(data);
}

void __s_indi_refresh_modems(TcorePlugin *indi_plugin)
{
	GSList *mp_list = tcore_server_get_modem_plugin_list(tcore_plugin_ref_server(indi_plugin));
	GSList *tmp;
	dbg("Processing %u present modems", g_slist_length(mp_list));

	for (tmp = mp_list; tmp; tmp = tmp->next)
		__s_indi_add_modem_plugin(indi_plugin, tmp->data);

	g_slist_free(mp_list);
}

void s_indi_storage_key_callback(enum tcore_storage_key key, void *value, void *user_data)
{
	s_indi_cp_state_info_type *state_info = NULL;
	GVariant *tmp = value;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(user_data);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}

	s_indi_assert(NULL != tmp);

	switch (key) {
	case STORAGE_KEY_PM_STATE: {
		GHashTableIter iter;
		gpointer key, value;
		gint pm_state = S_INDI_ZERO;

		if (!g_variant_is_of_type(tmp, G_VARIANT_TYPE_INT32)) {
			err("Wrong variant data type");
			return;
		}

		pm_state = g_variant_get_int32(tmp);

		dbg("PM state Value:[%d]", pm_state);

		g_hash_table_iter_init(&iter, priv_info->state_info);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			state_info = value;
			state_info->dormant_info.lcd_state = pm_state;
		}
	}
	break;

	default:
		s_indi_assert_not_reached();
	}
}

enum tcore_hook_return s_indi_on_hook_modem_power(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	struct tnoti_modem_power *modem_power = data;
	s_indi_assert(modem_power != NULL);

	S_INDI_NOT_USED(server);
	S_INDI_NOT_USED(command);
	S_INDI_NOT_USED(data_len);

	CORE_OBJECT_CHECK_RETURN(source, CORE_OBJECT_TYPE_MODEM, TCORE_HOOK_RETURN_CONTINUE);

	if (modem_power->state == MODEM_STATE_ERROR) { /* CP reset */
		TcorePlugin *indi_plugin = user_data;
		const char *cp_name = NULL;
		s_indi_cp_state_info_type *state_info = NULL;
		s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
		if (priv_info == NULL) {
			err("priv_info is NULL!!!");
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
		s_indi_assert(NULL != cp_name);
		s_indi_log_ex(cp_name, "MODEM_STATE_ERROR");

		if ((state_info = g_hash_table_lookup(priv_info->state_info, cp_name)) == NULL) {
			warn("BAILING OUT: [%s] not found", cp_name);
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		/* Remove all device states since PS releasing all contexts */
		g_hash_table_remove_all(state_info->device_info);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

enum tcore_hook_return s_indi_on_hook_ps_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	struct tnoti_ps_call_status *cstatus = data;
	TcorePlugin *indi_plugin = user_data;
	const char *cp_name = NULL;
	s_indi_cp_state_info_type *state_info = NULL;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	s_indi_assert(cstatus != NULL);

	S_INDI_NOT_USED(command);
	S_INDI_NOT_USED(data_len);

	CORE_OBJECT_CHECK_RETURN(source, CORE_OBJECT_TYPE_PS, TCORE_HOOK_RETURN_CONTINUE);

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	s_indi_assert(NULL != cp_name);

	s_indi_log_ex(cp_name, "cid(%d) state(%d) reason(%d)",
		cstatus->context_id, cstatus->state, cstatus->result);

	if (cstatus->state == S_INDI_PS_CALL_OK) {
		s_indi_log_ex(cp_name, "PS Call state - [PS_CALL_OK]");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	if ((state_info = g_hash_table_lookup(priv_info->state_info, cp_name)) == NULL) {
		warn("BAILING OUT: [%s] not found", cp_name);
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	s_indi_assert(source == state_info->co_ps);

	if (cstatus->state == S_INDI_PS_CALL_CONNECT) {
		GSList *l_context = NULL;
		CoreObject *co_context = NULL;
		gchar *dev_name = NULL;
		s_indi_dev_state_info_type *dev_state = NULL;
		enum tcore_storage_key key_service_state;
		Storage *strg_vconf = NULL;
		int role = CONTEXT_ROLE_UNKNOWN;
		gboolean data_allowed = FALSE;
		gboolean roaming_allowed = FALSE;

		s_indi_log_ex(cp_name, "PS Call state - [PS_CALL_CONNECT]");

		/* Fetch context with internet/tethering role */
		l_context = tcore_ps_ref_context_by_id(source, cstatus->context_id);
		while (l_context) {
			role = tcore_context_get_role(l_context->data);
			if (role == CONTEXT_ROLE_INTERNET || role == CONTEXT_ROLE_TETHERING || role == CONTEXT_ROLE_MMS) {
				co_context = l_context->data;
				break;
			}

			l_context = l_context->next;
		}

		if (!co_context) {
			err("INTERNET/TETHERING/MMS role not found");
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		dev_name = tcore_context_get_ipv4_devname(co_context); /* glib allocator */
		s_indi_assert(NULL != dev_name);

		/* Check if dev_name already exists */
		if (g_hash_table_lookup(state_info->device_info, dev_name)) {
			dbg("default connection is already connected");
			g_free(dev_name);
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		/* Update Cellular State */
		if (s_indi_str_has_suffix(cp_name, "0")) {
			key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE;
		} else if (s_indi_str_has_suffix(cp_name, "1")) {
			key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE2;
		} else {
			err("Un-handled CP");
			g_free(dev_name);
			s_indi_assert_not_reached();
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		/* Fresh */
		strg_vconf = tcore_server_find_storage(server, S_INDI_VCONF_STORAGE_NAME);
		s_indi_assert(NULL != strg_vconf);

		data_allowed = tcore_storage_get_bool(strg_vconf, STORAGE_KEY_3G_ENABLE);
		roaming_allowed = tcore_storage_get_bool(strg_vconf, STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING_BOOL);

		if (!data_allowed)
			return TCORE_HOOK_RETURN_CONTINUE;
		else if (state_info->roaming_status && !roaming_allowed)
			return TCORE_HOOK_RETURN_CONTINUE;

		/* Set Cellular state connected */
		if (role == CONTEXT_ROLE_INTERNET || role == CONTEXT_ROLE_TETHERING) {
			state_info->ps_state = S_INDI_CELLULAR_CONNECTED;
			tcore_storage_set_int(strg_vconf, key_service_state, S_INDI_CELLULAR_CONNECTED);
		} else if (role == CONTEXT_ROLE_MMS) {
			state_info->ps_state = S_INDI_CELLULAR_MMS_CONNECTED;
			tcore_storage_set_int(strg_vconf, key_service_state, S_INDI_CELLULAR_MMS_CONNECTED);
		}

		/* Initialize Packet indicator to Normal */
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, S_INDI_TRANSFER_NORMAL);
		state_info->cp_trans_state = S_INDI_TRANSFER_NORMAL;

		/* Create new dev state */
		dev_state = __s_indi_alloc_device_state(co_context, state_info);
		g_hash_table_insert(state_info->device_info, dev_name, dev_state);

		/* Start Updater */
		__s_indi_start_updater(indi_plugin, s_indi_strdup(cp_name));

	} else if (cstatus->state == S_INDI_PS_CALL_NO_CARRIER) {
		gchar *dev_name = NULL;
		GSList *l_context = tcore_ps_ref_context_by_id(source, cstatus->context_id);

		s_indi_log_ex(cp_name, "PS Call state - [PS_CALL_NO_CARRIER]");

		/* Remove all related contexts */
		while (l_context) {
			dev_name = tcore_context_get_ipv4_devname(l_context->data);
			if (dev_name != NULL) {
				g_hash_table_remove(state_info->device_info, dev_name);
				g_free(dev_name);
			}
			l_context = l_context->next;
		}
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

enum tcore_hook_return s_indi_on_hook_net_register(Server *server, CoreObject *source,
		enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	TcorePlugin *indi_plugin = user_data;
	const char *cp_name = NULL;
	s_indi_cp_state_info_type *state_info = NULL;
	gboolean active = FALSE;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	gboolean gsm_dtm_support = FALSE;
	struct tnoti_network_registration_status *regist_status = data;
	int roaming_status = S_INDI_ZERO;

	S_INDI_NOT_USED(command);
	S_INDI_NOT_USED(data_len);
	CORE_OBJECT_CHECK_RETURN(source, CORE_OBJECT_TYPE_NETWORK, TCORE_HOOK_RETURN_CONTINUE);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	cp_name = tcore_server_get_cp_name_by_plugin(tcore_object_ref_plugin(source));
	s_indi_assert(NULL != cp_name);
	s_indi_assert(NULL != regist_status);

	if ((state_info = g_hash_table_lookup(priv_info->state_info, cp_name)) == NULL) {
		warn("BAILING OUT: [%s] not found", cp_name);
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	roaming_status = state_info->roaming_status = regist_status->roaming_status;
	gsm_dtm_support = tcore_network_get_gsm_dtm_support(source);

	s_indi_log_ex(cp_name, "roam_status: [0x%x] dtm_support: [0x%x]",
		roaming_status, gsm_dtm_support);

	if (gsm_dtm_support)
		return TCORE_HOOK_RETURN_CONTINUE;

	active = (g_hash_table_size(state_info->device_info) >= S_INDI_ONE) ? TRUE : FALSE;

	if (active) {
		Storage *strg_vconf = NULL;
		GSList *co_list = NULL;
		CoreObject *co_call = NULL;
		unsigned int total_call_cnt = S_INDI_ZERO;
		enum telephony_network_service_type svc_type;
		enum tcore_storage_key key_service_state;
		gboolean roaming_allowed = FALSE;

		/* VCONF Mapper */
		if (s_indi_str_has_suffix(cp_name, "0")) {
			key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE;
		} else if (s_indi_str_has_suffix(cp_name, "1")) {
			key_service_state = STORAGE_KEY_PACKET_SERVICE_STATE2;
		} else {
			err("Un-handled CP");
			s_indi_assert_not_reached();
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		strg_vconf = tcore_server_find_storage(server, S_INDI_VCONF_STORAGE_NAME);
		roaming_allowed = tcore_storage_get_bool(strg_vconf, STORAGE_KEY_SETAPPL_STATE_DATA_ROAMING_BOOL);

		svc_type = regist_status->service_type;
		s_indi_log_ex(cp_name, "srvc_type(%d), roaming_allowed(%d)",
			svc_type, roaming_allowed);

		/**
		 * If Roaming is NOT allowed and indication provides Roaming
		 * status Available, there is a mismatch.
		 * Set Cellular state OFF.
		 */
		if (state_info->ps_state != S_INDI_CELLULAR_OFF && !roaming_allowed && roaming_status) {
			/* Set Cellular State OFF */
			tcore_storage_set_int(strg_vconf, key_service_state, S_INDI_CELLULAR_OFF);

			/*
			 * Indicator need not know worry about roaming status. packet service plugin
			 * should take care of de-activating the contexts when roaming is enabled and
			 * network enters roaming. When all the contexts associated with that network
			 * is de-activated. Indicator plugin will automatically ps status for that
			 * CP to S_INDI_CELLULAR_OFF
			 */
			state_info->ps_state = S_INDI_CELLULAR_OFF; /* Update cache */

			s_indi_log_ex(cp_name, "PS Call status - [DISCONNECTED]");
			return TCORE_HOOK_RETURN_CONTINUE;
		}

		if (svc_type < NETWORK_SERVICE_TYPE_2G || svc_type > NETWORK_SERVICE_TYPE_2_5G_EDGE)
			return TCORE_HOOK_RETURN_CONTINUE;

		co_list = tcore_plugin_get_core_objects_bytype(tcore_object_ref_plugin(source), CORE_OBJECT_TYPE_CALL);
		if (!co_list) {
			err("[ error ] co_list : NULL");
			return TCORE_HOOK_RETURN_CONTINUE;
		}
		s_indi_assert(g_slist_length(co_list) == S_INDI_ONE);

		co_call = (CoreObject *)co_list->data;
		g_slist_free(co_list);

		total_call_cnt = tcore_call_object_total_length(co_call);
		s_indi_log_ex(cp_name, "totall call cnt (%d)", total_call_cnt);

		if (total_call_cnt > S_INDI_ONE) {
			s_indi_cellular_state pkg_state = S_INDI_CELLULAR_UNKNOWN;
			pkg_state = tcore_storage_get_int(strg_vconf, key_service_state);
			if (pkg_state != S_INDI_CELLULAR_OFF) {
				tcore_storage_set_int(strg_vconf, key_service_state, S_INDI_CELLULAR_OFF);
				state_info->ps_state = S_INDI_CELLULAR_OFF; /* Update cache */
			}
		}
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

gboolean __s_indi_handle_voice_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, const char *cp_name, s_indi_cp_state_info_type *state_info)
{
	CoreObject *co_network = NULL;
	enum tcore_storage_key vconf_key;
	Storage *strg_vconf;
	enum telephony_network_service_type svc_type;
	gboolean show_icon = TRUE;

	if (g_hash_table_size(state_info->device_info) == S_INDI_ZERO) {
		s_indi_log_ex(cp_name, "PS state is already OFF");
		return TRUE;
	}

	co_network = tcore_plugin_ref_core_object(tcore_object_ref_plugin(state_info->co_ps),
					CORE_OBJECT_TYPE_NETWORK);

	if (co_network) {
		gboolean gsm_dtm_support = FALSE;
		gsm_dtm_support = tcore_network_get_gsm_dtm_support(co_network);
		if (gsm_dtm_support) {
			s_indi_log_ex(cp_name, "GSM DTM supported! UI need not be synchronized");
			return TRUE;
		}
	}

	/* Mapping VCONF keys */
	if (s_indi_str_has_suffix(cp_name, "0")) {
		vconf_key = STORAGE_KEY_PACKET_SERVICE_STATE;
	} else if (s_indi_str_has_suffix(cp_name, "1")) {
		vconf_key = STORAGE_KEY_PACKET_SERVICE_STATE2;
	} else {
		s_indi_assert_not_reached();
		return TRUE;
	}

	tcore_network_get_service_type(co_network, &svc_type);

	switch (svc_type) {
	case NETWORK_SERVICE_TYPE_2G:
	case NETWORK_SERVICE_TYPE_2_5G:
	case NETWORK_SERVICE_TYPE_2_5G_EDGE:
		show_icon = FALSE;
	break;

	case NETWORK_SERVICE_TYPE_3G:
	case NETWORK_SERVICE_TYPE_HSDPA:
		if (tcore_object_ref_plugin(co_network) != tcore_object_ref_plugin(source))
			show_icon = FALSE;
	break;

	default:
	break;
	}

	s_indi_log_ex(cp_name, "RAT: [0x%x], ps_state: [0x%x], show_icon[%d]",
		svc_type, state_info->ps_state, show_icon);

	if (show_icon == TRUE) {
		if (state_info->ps_state == S_INDI_CELLULAR_OFF) {
			state_info->ps_state = S_INDI_CELLULAR_CONNECTED;
			goto OUT;
		}
		return TRUE;
	}

	switch (command) {
	case TNOTI_CALL_STATUS_IDLE: {
		int total_call_cnt = S_INDI_ZERO;
		total_call_cnt = tcore_call_object_total_length(source);
		if (total_call_cnt > S_INDI_ONE) {
			s_indi_log_ex(cp_name, "Call is still connected");
			return TRUE;
		}
		state_info->ps_state = S_INDI_CELLULAR_CONNECTED;
	}
	break;

	case TNOTI_CALL_STATUS_DIALING:
	case TNOTI_CALL_STATUS_INCOMING:
	case TNOTI_CALL_STATUS_ACTIVE: {
		state_info->ps_state = S_INDI_CELLULAR_OFF;
	}
	break;

	default: {
		s_indi_log_ex(cp_name, "Unexpected command: [0x%x]", command);
		s_indi_assert_not_reached();
		return TRUE;
	}
	}

OUT:
	/* Update PS Call state */
	strg_vconf = tcore_server_find_storage(server, S_INDI_VCONF_STORAGE_NAME);
	if (state_info->ps_state != tcore_storage_get_int(strg_vconf, vconf_key)) {
		tcore_storage_set_int(strg_vconf, vconf_key, state_info->ps_state);
		s_indi_log_ex(cp_name, "PS Call status - [%s]",
			(state_info->ps_state == S_INDI_CELLULAR_CONNECTED ? "CONNECTED"
			: (state_info->ps_state == S_INDI_CELLULAR_OFF ? "DISCONNECTED"
			: (state_info->ps_state == S_INDI_CELLULAR_USING ? "IN USE" : "UNKNOWN"))));
	}

	return TRUE;
}

enum tcore_hook_return s_indi_on_hook_voice_call_status(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	TcorePlugin *indi_plugin = user_data;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(indi_plugin);
	const char *cp_name = NULL;
	s_indi_cp_state_info_type *state_info = NULL;

	GHashTableIter iter;
	gpointer key, value;

	S_INDI_NOT_USED(data_len);
	S_INDI_NOT_USED(data);

	CORE_OBJECT_CHECK_RETURN(source, CORE_OBJECT_TYPE_CALL, TCORE_HOOK_RETURN_CONTINUE);
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	/* Update all modem states */
	g_hash_table_iter_init(&iter, priv_info->state_info);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		cp_name = key;
		state_info = value;

		(void)__s_indi_handle_voice_call_status(server, source, command,
				cp_name, state_info);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

enum tcore_hook_return s_indi_on_hook_modem_plugin_added(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	s_indi_assert(NULL != data);
	s_indi_assert(NULL != user_data);

	S_INDI_NOT_USED(server);
	S_INDI_NOT_USED(source);
	S_INDI_NOT_USED(command);
	S_INDI_NOT_USED(data_len);

	__s_indi_add_modem_plugin(user_data, data);

	return TCORE_HOOK_RETURN_CONTINUE;
}

enum tcore_hook_return s_indi_on_hook_modem_plugin_removed(Server *server, CoreObject *source,
	enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	s_indi_assert(NULL != data);
	s_indi_assert(NULL != user_data);

	S_INDI_NOT_USED(server);
	S_INDI_NOT_USED(source);
	S_INDI_NOT_USED(command);
	S_INDI_NOT_USED(data_len);

	__s_indi_remove_modem_plugin(user_data, data);

	return TCORE_HOOK_RETURN_CONTINUE;
}

gboolean s_indi_init(TcorePlugin *plugin)
{
	Server *server = NULL;
	s_indi_private_info *priv_info = NULL;

	priv_info = s_indi_malloc0(sizeof(*priv_info));
	if (priv_info == NULL) {
		err("Memory allocation failed!!");
		return FALSE;
	}
	if (tcore_plugin_link_user_data(plugin, priv_info) != TCORE_RETURN_SUCCESS) {
		err("Failed to link private data");
		s_indi_free(priv_info);
		return FALSE;
	}

	server = tcore_plugin_ref_server(plugin);

	/* Initialize VCONF => CP_NAME mapping */
	priv_info->vconf_info = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, s_indi_free_func);

	/* Initialize State Information */
	priv_info->state_info = g_hash_table_new_full(g_str_hash, g_str_equal,
		s_indi_free_func, __s_indi_state_info_value_destroy_notification);
	if (priv_info->state_info == NULL
		|| priv_info->vconf_info == NULL) {
		err("Memory allocation problem! Bailing Out");
		goto OUT;
	}

	/* Register vconf key callbacks */
	__s_indi_register_vconf_key(STORAGE_KEY_PM_STATE, plugin, NULL);

	/* Server Hooks*/
	tcore_server_add_notification_hook(server, TNOTI_MODEM_POWER, s_indi_on_hook_modem_power, plugin);
	tcore_server_add_notification_hook(server, TNOTI_PS_CALL_STATUS, s_indi_on_hook_ps_call_status, plugin);
	tcore_server_add_notification_hook(server, TNOTI_NETWORK_REGISTRATION_STATUS, s_indi_on_hook_net_register, plugin);

	/* For 2G PS suspend/resume */
	tcore_server_add_notification_hook(server, TNOTI_CALL_STATUS_IDLE, s_indi_on_hook_voice_call_status, plugin);
	tcore_server_add_notification_hook(server, TNOTI_CALL_STATUS_DIALING, s_indi_on_hook_voice_call_status, plugin);
	tcore_server_add_notification_hook(server, TNOTI_CALL_STATUS_INCOMING, s_indi_on_hook_voice_call_status, plugin);
	tcore_server_add_notification_hook(server, TNOTI_CALL_STATUS_ACTIVE, s_indi_on_hook_voice_call_status, plugin);

	/* For new Modems */
	tcore_server_add_notification_hook(server, TNOTI_SERVER_ADDED_MODEM_PLUGIN, s_indi_on_hook_modem_plugin_added, plugin);
	tcore_server_add_notification_hook(server, TNOTI_SERVER_REMOVED_MODEM_PLUGIN, s_indi_on_hook_modem_plugin_removed, plugin);

	/* Add existing Modems */
	__s_indi_refresh_modems(plugin);

	return TRUE;

OUT:
	s_indi_deinit(plugin);
	return FALSE;
}

void s_indi_deinit(TcorePlugin *plugin)
{
	Server *server = NULL;
	GList *iter;
	s_indi_cp_state_info_type *state_info = NULL;
	TcorePlugin *modem_plugin = NULL;
	s_indi_private_info *priv_info = __s_indi_get_priv_info(plugin);

	/* Remove Hooks */
	server = tcore_plugin_ref_server(plugin);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_modem_power);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_ps_call_status);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_net_register);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_voice_call_status);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_modem_plugin_added);
	tcore_server_remove_notification_hook(server, s_indi_on_hook_modem_plugin_removed);

	/* Remove key callback */
	__s_indi_unregister_vconf_key(STORAGE_KEY_PM_STATE, plugin, NULL);

	/* Destroy all watched modems */
	if (priv_info == NULL) {
		err("priv_info is NULL!!!");
		return;
	}
	iter = g_hash_table_get_values(priv_info->state_info);
	while (iter) {
		state_info = iter->data;
		modem_plugin = tcore_object_ref_plugin(state_info->co_ps);
		__s_indi_remove_modem_plugin(plugin, modem_plugin);

		iter = g_list_delete_link(iter, iter);
	}

	/* Decrement hash table reference */
	g_hash_table_destroy(priv_info->state_info);
	g_hash_table_destroy(priv_info->vconf_info);

	/* Finalize */
	s_indi_free(priv_info);
	tcore_plugin_link_user_data(plugin, NULL);
}
