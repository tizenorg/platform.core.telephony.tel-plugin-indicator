/*
 * tel-plugin-indicator
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: DongHoo Park <donghoo.park@samsung.com>
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
 *
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
#define DATABASE_PATH		"/opt/dbspace/.dnet.db"
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

struct indicator_device_state {
	gchar *devname;
	gboolean active;
	guint64 prev_rx;
	guint64 prev_tx;
	guint64 curr_rx;
	guint64 curr_tx;
};

//global variable
static struct  indicator_device_state indicator_info = {
	NULL,FALSE,0,0,0,0
};

static GSource* src;
static gboolean _indicator_update_callback(gpointer user_data);

static void _indicator_initialize(Server *s)
{
	indicator_info.prev_rx = 0;
	indicator_info.prev_tx = 0;
	indicator_info.curr_rx = 0;
	indicator_info.curr_tx = 0;
}

static gboolean _indicator_start_updater(Server *s)
{
	Storage *strg_vconf;
	gpointer vconf_handle;

	dbg("indicator is started");

	strg_vconf = tcore_server_find_storage(s, "vconf");
	vconf_handle = tcore_storage_create_handle(strg_vconf, "vconf");
	if (!vconf_handle)
		err("fail to create vconf db_handle");

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_NORMAL_CONNECTED);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_NORMAL);

	if(src != 0)
		return FALSE;

	_indicator_initialize(s);

	src = g_timeout_source_new_seconds(INDICATOR_UPDATE_INTERVAL);
	g_source_set_callback(src, _indicator_update_callback, s, NULL);
	g_source_set_priority(src, G_PRIORITY_HIGH);
	g_source_attach(src, NULL);
	g_source_unref(src);

	return TRUE;
}

static gboolean _indicator_stop_updater(Server *s)
{
	Storage *strg_vconf;
	gpointer vconf_handle;
	int t_rx = 0, t_tx = 0;

	dbg("indicator is stopped");
	strg_vconf = tcore_server_find_storage(s, "vconf");
	vconf_handle = tcore_storage_create_handle(strg_vconf, "vconf");
	if (!vconf_handle)
		err("fail to create vconf db_handle");

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_SERVICE_STATE, CELLULAR_OFF);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_PACKET_INDICATOR_STATE, INDICATOR_NORMAL);

	t_rx = tcore_storage_get_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV);
	t_tx = tcore_storage_get_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT);
	t_rx += (int)indicator_info.curr_rx;
	t_tx += (int)indicator_info.curr_tx;

	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_RCV, t_rx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_TOTAL_SNT, t_tx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_LAST_RCV, (int)indicator_info.curr_rx);
	tcore_storage_set_int(strg_vconf, STORAGE_KEY_CELLULAR_PKT_LAST_SNT, (int)indicator_info.curr_tx);

	if(src == 0)
		return TRUE;

	g_source_destroy(src);
	src = 0;

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

static gboolean _indicator_get_pktcnt(gpointer user_data)
{
	FILE *pf = NULL;
	gint proc_ver = 0;
	char *res;
	gchar buff[INDICATOR_BUFF_SIZE];

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

		if ( g_strcmp0(ifname, indicator_info.devname) == 0 ){
			indicator_info.prev_rx = indicator_info.curr_rx;
			indicator_info.prev_tx = indicator_info.curr_tx;
			indicator_info.curr_rx = rx_pkt;
			indicator_info.curr_tx = tx_pkt;
			break;
		}
	}

	fclose(pf);
	return TRUE;
}

static gboolean _indicator_update(Server *s)
{
	guint64 rx_changes = 0;
	guint64 tx_changes = 0;
	Storage *strg_vconf;
	gpointer vconf_handle;

	strg_vconf = tcore_server_find_storage(s, "vconf");
	vconf_handle = tcore_storage_create_handle(strg_vconf, "vconf");
	if (!vconf_handle)
		err("fail to create vconf db_handle");

	if(!indicator_info.active) return FALSE;

	rx_changes = indicator_info.curr_rx - indicator_info.prev_rx;
	tx_changes = indicator_info.curr_tx - indicator_info.prev_tx;

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
	Server *s = NULL;

	s = (Server *)user_data;

	rv = _indicator_get_pktcnt(NULL);
	if(!rv){
		src = 0;
		return FALSE;
	}

	rv = _indicator_update(s);
	if(!rv){
		src = 0;
		return FALSE;
	}

	return TRUE;
}

static enum tcore_hook_return __on_hook_powered(Server *s, CoreObject *source,
		enum tcore_notification_command command, unsigned int data_len, void *data, void *user_data)
{
	struct tnoti_modem_power *modem_power = NULL;

	dbg("powered event called");
	g_return_val_if_fail(data != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	modem_power = (struct tnoti_modem_power *)data;
	if ( modem_power->state == MODEM_STATE_ERROR ){
		indicator_info.active = FALSE;
		g_free(indicator_info.devname);
		indicator_info.devname = NULL;
		_indicator_stop_updater(s);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static enum tcore_hook_return __on_hook_callstatus(Server *s, CoreObject *source,
		enum tcore_notification_command command, unsigned int data_len, void *data,
		void *user_data)
{
	unsigned int con_id = 0;
	CoreObject *co_ps = NULL, *co_context = NULL;
	struct tnoti_ps_call_status *cstatus = NULL;

	dbg("call status event");
	g_return_val_if_fail(data != NULL, TCORE_HOOK_RETURN_STOP_PROPAGATION);

	co_ps = source;
	dbg("ps object(%p)", co_ps);
	co_context = tcore_ps_ref_context_by_role(co_ps, CONTEXT_ROLE_INTERNET);
	con_id = tcore_context_get_id(co_context);
	dbg("context(%p) con_id(%d)", co_context, con_id);

	cstatus = (struct tnoti_ps_call_status *) data;
	dbg("call status event cid(%d) state(%d)", cstatus->context_id, cstatus->state);

	if(con_id != cstatus->context_id)
		return TCORE_HOOK_RETURN_CONTINUE;

	if (cstatus->state == PS_DATA_CALL_CTX_DEFINED) {
		/* do nothing. */
		dbg("Just noti for PDP define complete, do nothing.");
		return TCORE_HOOK_RETURN_CONTINUE;
	}
	else if (cstatus->state == PS_DATA_CALL_CONNECTED) {
		indicator_info.active = TRUE;
		indicator_info.devname = tcore_context_get_ipv4_devname(co_context);
		_indicator_start_updater(s);
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	indicator_info.active = FALSE;
	g_free(indicator_info.devname);
	indicator_info.devname = NULL;
	_indicator_stop_updater(s);

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
	s = tcore_plugin_ref_server(p);
	tcore_server_add_notification_hook(s, TNOTI_MODEM_POWER, __on_hook_powered, NULL);
	tcore_server_add_notification_hook(s, TNOTI_PS_CALL_STATUS, __on_hook_callstatus, NULL);
	dbg("initialized Indicator plugin!");
	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	dbg("i'm unload!");
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
