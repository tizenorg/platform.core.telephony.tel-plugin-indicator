/*
 * tel-plugin-indicator
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd. All rights reserved.
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

#include <tcore.h>
#include <server.h>
#include <plugin.h>
#include <storage.h>
#include <co_ps.h>
#include <co_context.h>

#define INDICATOR_UPDATE_INTERVAL	1
#define INDICATOR_PROCFILE		"/proc/net/dev"
#define INDICATOR_BUFF_SIZE		4096
#define NO_RX_PKT_TIMEOUT	30
//enum

typedef enum _cellular_state {
	CELLULAR_OFF = 0x00,
	CELLULAR_NORMAL_CONNECTED = 0x01,
	CELLULAR_SECURE_CONNECTED = 0x02,
	CELLULAR_USING = 0x03,
} cellular_state;

typedef enum _indicator_state {
	INDICATOR_NORMAL = 0x00,
	INDICATOR_RX = 0x01,
	INDICATOR_TX = 0x02,
	INDICATOR_RXTX = 0x03,
} indicator_state;

typedef struct _indicator_device_state {
	gchar *devname;
	gboolean active;
	guint64 prev_rx;
	guint64 prev_tx;
	guint64 curr_rx;
	guint64 curr_tx;
}indicator_device_state;

typedef struct _indicator_data {
	indicator_device_state indicator_info;
	GSource* src;
}indicator_data;

static gboolean _indicator_update_callback(gpointer user_data);

static void _indicator_initialize(indicator_data *data)
{
	if (data) {
		data->indicator_info.prev_rx = 0;
		data->indicator_info.prev_tx = 0;
		data->indicator_info.curr_rx = 0;
		data->indicator_info.curr_tx = 0;
	} else {
		err("user data is NULL");
	}
}


static gboolean _indicator_start_updater(Server *s, TcorePlugin *plugin)
{
	TcoreStorage *strg_vconf;
	indicator_data *data = NULL;

	dbg("indicator is started");
	strg_vconf = tcore_server_find_storage(s, "vconf");

	data = tcore_plugin_ref_user_data(plugin);
	if(!data) {
		err("user data is NULL");
		return FALSE;
	}

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_NORMAL_CONNECTED);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_NORMAL);

	if(data->src != 0) {
		return FALSE;
	}

	_indicator_initialize(data);

	data->src = g_timeout_source_new_seconds(INDICATOR_UPDATE_INTERVAL);
	g_source_set_callback(data->src, _indicator_update_callback, plugin, NULL);
	g_source_set_priority(data->src, G_PRIORITY_HIGH);
	g_source_attach(data->src, NULL);
	g_source_unref(data->src);

	return TRUE;
}

static gboolean _indicator_stop_updater(Server *s, TcorePlugin *plugin)
{
	TcoreStorage *strg_vconf;
	int t_rx = 0, t_tx = 0;
	indicator_data *data = NULL;

	dbg("indicator is stopped");
	data = tcore_plugin_ref_user_data(plugin);
	if (!data) {
		err("user data is NULL");
		return FALSE;
	}
	strg_vconf = tcore_server_find_storage(s, "vconf");

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_OFF);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_NORMAL);

	t_rx = tcore_storage_get_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV);
	t_tx = tcore_storage_get_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT);
	t_rx += (int)data->indicator_info.curr_rx;
	t_tx += (int)data->indicator_info.curr_tx;

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV, t_rx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT, t_tx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_LAST_RCV, (int)data->indicator_info.curr_rx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_LAST_SNT, (int)data->indicator_info.curr_tx);

	if(data->src == 0){
		return TRUE;
	}

	g_source_destroy(data->src);
	data->src = 0;

	return TRUE;
}

static gint _indicator_get_proc_ver(gchar *buff)
{
	if (strstr(buff, "compressed")) return 3;
	if (strstr(buff, "bytes")) return 2;
	return 1;
}

static gint _indicator_get_pkt(gchar *buff, gint proc_ver, guint64 *rx_pkt, guint64 *tx_pkt)
{
	gint result = -1;
	gchar s_rx[100];
	gchar s_tx[100];

	memset(s_rx, 0 , 100);
	memset(s_tx, 0 , 100);

	if (buff == NULL)
		return result;

	switch (proc_ver) {
	case 3:
		result = sscanf(buff,
				"%s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s",
				s_rx, s_tx);
		break;
	case 2:
		result = sscanf(buff,
				"%s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s",
				s_rx, s_tx);
		break;
	case 1:
		result = sscanf(buff,
				"%s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %*s %*s %*s %*s",
				s_rx, s_tx);
		break;
	default:
		dbg("stats unknown version");
		break;
	}

	*rx_pkt = g_ascii_strtoull(s_rx, NULL, 10);
	*tx_pkt = g_ascii_strtoull(s_tx, NULL, 10);

	return result;
}

static gboolean _indicator_get_pktcnt(indicator_data *data)
{
	FILE *pf = NULL;
	gint proc_ver = 0;
	char *res;
	gchar buff[INDICATOR_BUFF_SIZE];

	if (!data) {
		err("user data is NULL");
		return FALSE;
	}

	pf = fopen(INDICATOR_PROCFILE, "r");
	if (pf == NULL) {
		err("indicator fail to open file(%s), errno(%d)", INDICATOR_PROCFILE, errno);
		return FALSE;
	}

	res = fgets(buff, sizeof(buff), pf);
	if (res == NULL)
		err("fegts fails");
	res = fgets(buff, sizeof(buff), pf);
	if (res == NULL)
		err("fegts fails");
	proc_ver = _indicator_get_proc_ver(buff);

	while (fgets(buff, sizeof(buff), pf)) {
		gint result = 0;
		guint64 rx_pkt = 0;
		guint64 tx_pkt = 0;
		gchar *ifname, *entry;

		ifname = buff;
		while (*ifname == ' ')
			ifname++;
		entry = strrchr(ifname, ':');
		*entry++ = 0;

		result = _indicator_get_pkt(entry, proc_ver, &rx_pkt, &tx_pkt);
		if (result <= 0) {
			err("stats fail to get proc field");
			fclose(pf);
			return FALSE;
		}

		if ( g_strcmp0(ifname, data->indicator_info.devname) == 0 ){
			data->indicator_info.prev_rx = data->indicator_info.curr_rx;
			data->indicator_info.prev_tx = data->indicator_info.curr_tx;
			data->indicator_info.curr_rx = rx_pkt;
			data->indicator_info.curr_tx = tx_pkt;
			break;
		}
	}

	fclose(pf);
	return TRUE;
}

static gboolean _indicator_update(Server *s, indicator_data *data)
{
	guint64 rx_changes = 0;
	guint64 tx_changes = 0;
	TcoreStorage *strg_vconf;

	strg_vconf = tcore_server_find_storage(s, "vconf");
	if(!data) return FALSE;
	if(!data->indicator_info.active) return FALSE;

	rx_changes = data->indicator_info.curr_rx - data->indicator_info.prev_rx;
	tx_changes = data->indicator_info.curr_tx - data->indicator_info.prev_tx;

	if (rx_changes != 0 || tx_changes != 0)
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_USING);
	else
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_NORMAL_CONNECTED);

	if (rx_changes > 0 && tx_changes > 0)
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_RXTX);
	else if (rx_changes > 0 && tx_changes == 0)
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_RX);
	else if (rx_changes == 0 && tx_changes > 0)
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_TX);
	else
		tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_NORMAL);

	return TRUE;
}

static gboolean _indicator_update_callback(gpointer user_data)
{
	gboolean rv = FALSE;
	TcorePlugin *indicator_plugin = NULL;
	Server *s = NULL;
	indicator_data *data = NULL;

	indicator_plugin = (TcorePlugin *)user_data;
	s = tcore_plugin_ref_server(indicator_plugin);
	data = tcore_plugin_ref_user_data(indicator_plugin);
	if(!data){
		err("user data is NULL");
		return FALSE;
	}

	rv = _indicator_get_pktcnt(data);
	if(!rv){
		data->src = 0;
		return FALSE;
	}

	rv = _indicator_update(s, data);
	if(!rv){
		data->src = 0;
		return FALSE;
	}

	return TRUE;
}

static TcoreHookReturn __on_hook_modem_powered(TcorePlugin *source,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	TelModemPowerStatus *power_status = NULL;

	dbg("powered event called");
	tcore_check_return_value(data != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	power_status = (TelModemPowerStatus *)data;
	if (*power_status == TEL_MODEM_POWER_ERROR) {
		Server *s = NULL;
		indicator_data *data = NULL;
		TcorePlugin *plugin = (TcorePlugin *)user_data;

		data = tcore_plugin_ref_user_data(plugin);
		if (data) {
			data->indicator_info.active = FALSE;
			g_free(data->indicator_info.devname);
			data->indicator_info.devname = NULL;
			s = tcore_plugin_ref_server(source);
			if (s) {
				_indicator_stop_updater(s, plugin);
			}
		}else {
			err("user data is NULL");
		}
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_ps_callstatus(TcorePlugin *source,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	unsigned int con_id = 0;
	CoreObject *co_ps = NULL, *co_context = NULL;
	TcorePsCallStatusInfo *cstatus = NULL;
	TcorePlugin *plugin = NULL;
	indicator_data *indata = NULL;
	Server *s = NULL;
	gboolean res = FALSE;

	dbg("call status event");
	tcore_check_return_value((data != NULL) || (user_data != NULL), TCORE_HOOK_RETURN_STOP_PROPAGATION);

	plugin = (TcorePlugin *)user_data;
	indata = tcore_plugin_ref_user_data(plugin);
	tcore_check_return_value((indata != NULL) , TCORE_HOOK_RETURN_STOP_PROPAGATION);

	s = tcore_plugin_ref_server(source);
	co_ps = tcore_plugin_ref_core_object(source, CORE_OBJECT_TYPE_PS);
	dbg("ps object(%p)", co_ps);
	co_context = tcore_ps_ref_context_by_role(co_ps, TCORE_CONTEXT_ROLE_INTERNET);
	res = tcore_context_get_id(co_context, &con_id);
	if (res == FALSE) {
		err("get context id failed");
		return TCORE_HOOK_RETURN_CONTINUE;
	}
	dbg("context(%p) con_id(%d)", co_context, con_id);

	cstatus = (TcorePsCallStatusInfo *) data;
	if (!cstatus) {
		err("PS status is NULL");
		return TCORE_HOOK_RETURN_CONTINUE;
	}
	dbg("call status event cid(%d) state(%d)", cstatus->context_id, cstatus->state);

	if(con_id != cstatus->context_id)
		return TCORE_HOOK_RETURN_CONTINUE;

	if (cstatus->state == TCORE_PS_CALL_STATE_CTX_DEFINED) {
		/* do nothing. */
		dbg("Just noti for PDP define complete, do nothing.");
		return TCORE_HOOK_RETURN_CONTINUE;
	}
	else if (cstatus->state == TCORE_PS_CALL_STATE_CONNECTED) {
		indata->indicator_info.active = TRUE;
		res = tcore_context_get_ipv4_devname(co_context, &indata->indicator_info.devname);
		if (res == FALSE) {
			err("get context ipv4 failed");
			return TCORE_HOOK_RETURN_CONTINUE;
		}
		_indicator_start_updater(s, plugin);
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	indata->indicator_info.active = FALSE;
	g_free(indata->indicator_info.devname);
	indata->indicator_info.devname = NULL;
	_indicator_stop_updater(s, plugin);
	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_modem_plugin_added(Server *s,
			TcoreServerNotification command,
			guint data_len, void *data, void *user_data)
{
	TcorePlugin *modem_plugin;
	TcorePlugin *indicator_plugin = (TcorePlugin *)user_data;

	modem_plugin = (TcorePlugin *)data;
	tcore_check_return_value_assert(NULL != modem_plugin, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	tcore_plugin_add_notification_hook(modem_plugin, TCORE_NOTIFICATION_MODEM_POWER,
										__on_hook_modem_powered, indicator_plugin);
	tcore_plugin_add_notification_hook(modem_plugin, TCORE_NOTIFICATION_PS_CALL_STATUS,
										__on_hook_ps_callstatus, indicator_plugin);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn __on_hook_modem_plugin_removed(Server *s,
			TcoreServerNotification command,
			guint data_len, void *data, void *user_data)
{
	TcorePlugin *modem_plugin;

	modem_plugin = (TcorePlugin *)data;
	tcore_check_return_value_assert(NULL != modem_plugin, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	tcore_plugin_remove_notification_hook(modem_plugin, TCORE_NOTIFICATION_MODEM_POWER,
					__on_hook_modem_powered);
	tcore_plugin_remove_notification_hook(modem_plugin, TCORE_NOTIFICATION_PS_CALL_STATUS,
					__on_hook_ps_callstatus);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean on_load()
{
	dbg("Indicator plugin load!");
	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	Server *s = NULL;
	GSList *list = NULL;
	indicator_data *data = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;

	data = tcore_malloc0(sizeof(indicator_data));
	if (!data) {
		err("Failed to allocate memory");
		return FALSE;
	}
	ret = tcore_plugin_link_user_data(p, data);
	if (ret != TEL_RETURN_SUCCESS) {
		err("Unable to link user data");
		free(data);
		return FALSE;
	}

	s = tcore_plugin_ref_server(p);
	list = tcore_server_get_modem_plugin_list(s);
	while (list) {	/* Process for pre-loaded Modem Plug-in */
		TcorePlugin *modem_plugin;

		modem_plugin = list->data;
		if ( NULL != modem_plugin) {
			tcore_plugin_add_notification_hook(modem_plugin, TCORE_NOTIFICATION_MODEM_POWER,
												__on_hook_modem_powered, p);
			tcore_plugin_add_notification_hook(modem_plugin, TCORE_NOTIFICATION_PS_CALL_STATUS,
												__on_hook_ps_callstatus, p);
		}
		list = g_slist_next(list);
	}
	g_slist_free(list);

	/* Register for post-loaded Modem Plug-ins */
	tcore_server_add_notification_hook(s, TCORE_SERVER_NOTIFICATION_ADDED_MODEM_PLUGIN,
					__on_hook_modem_plugin_added, p);
	tcore_server_add_notification_hook(s, TCORE_SERVER_NOTIFICATION_REMOVED_MODEM_PLUGIN,
					__on_hook_modem_plugin_removed, p);
	dbg("initialized Indicator plugin!");
	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	indicator_data *data = NULL;
	dbg("i'm unload!");

	data = tcore_plugin_ref_user_data(p);
	if (data->src) {
		g_source_destroy(data->src);
		data->src = NULL;
	}
	tcore_free(data);
	data = NULL;
	return;
}

struct tcore_plugin_define_desc plugin_define_desc =
{
	.name = "INDICATOR",
	.priority = TCORE_PLUGIN_PRIORITY_MID + 2,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
