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

#pragma once

#include <glib.h>
#include <tcore.h>

#define s_indi_assert(cond) g_assert(cond)
#define s_indi_assert_not_reached() g_assert_not_reached()
#define s_indi_malloc0(sz) g_malloc0(sz)
#define s_indi_free_func g_free
#define s_indi_free(p) s_indi_free_func(p)
#define s_indi_strdup(str) g_strdup(str)
#define s_indi_str_has_suffix(str, pre) g_str_has_suffix(str, pre)

#define S_INDI_ZERO (0)
#define S_INDI_ONE (1)
#define S_INDI_FIVE (5)
#define S_INDI_SIPC_ITER_START S_INDI_ONE
#define S_INDI_SIPC_ITER_END (255)
#define S_INDI_MINUS_ONE (-1)
#define S_INDI_NOT_USED(var) ((var) = (var))
#define S_INDI_SIPC_MSG_ID(hdr)				((hdr).main_cmd << 8 | (hdr).sub_cmd)

typedef enum {
	S_INDI_CELLULAR_UNKNOWN = -1,
	S_INDI_CELLULAR_OFF = 0x00,
	S_INDI_CELLULAR_CONNECTED = 0x01,
	S_INDI_CELLULAR_MMS_CONNECTED = 0x02,
	S_INDI_CELLULAR_USING = 0x03,
} s_indi_cellular_state;

typedef enum {
	S_INDI_TRANSFER_UNKNOWN = -1,
	S_INDI_TRANSFER_NORMAL = 0x00,
	S_INDI_TRANSFER_RX = 0x01,
	S_INDI_TRANSFER_TX = 0x02,
	S_INDI_TRANSFER_RXTX = 0x03,
} s_indi_transfer_state;

typedef enum {
	S_INDI_LCD_UNKNOWN = -1,
	S_INDI_LCD_ON = 0x01,
	S_INDI_LCD_DIM = 0x02,
	S_INDI_LCD_OFF = 0x03
} s_indi_lcd_state;

typedef enum {
	S_INDI_PS_CALL_OK = 0x00,
	S_INDI_PS_CALL_CONNECT = 0x01,
	S_INDI_PS_CALL_NO_CARRIER = 0x03,
} s_indi_ps_call_state;

struct global_data {
	unsigned int id_current;
	unsigned int id_start;
	unsigned int id_end;
};

typedef struct s_indi_cp_state_info_type_struct s_indi_cp_state_info_type;
typedef struct {
	gchar *mccmnc;
	gboolean b_vconf_checker;
	s_indi_lcd_state lcd_state;
	int lcd_on_timeout;
	int lcd_off_timeout;
	int dormant_cnt;
	gboolean is_dormant;
	gboolean is_dormant_set;
	s_indi_cp_state_info_type *parent;
} s_indi_dormancy_info_type;

struct s_indi_cp_state_info_type_struct{
	CoreObject *co_ps;
	GSource *src;
	GHashTable *device_info; /* HashTable of s_indi_dev_state_info_type with key = dev_name */
	s_indi_dormancy_info_type dormant_info;
	s_indi_cellular_state ps_state;
	s_indi_transfer_state cp_trans_state;
	unsigned long long rx_total;
	unsigned long long tx_total;
	int no_rx_pckt; /* Last time since packed was received in seconds */
	gboolean roaming_status;
	int curr_timer_cp;
	gboolean curr_fdy_state_cp;
};

typedef struct {
	CoreObject *ps_context;
	s_indi_cp_state_info_type *parent;
	unsigned long prev_rx;
	unsigned long prev_tx;
	unsigned long curr_rx;
	unsigned long curr_tx;
} s_indi_dev_state_info_type;
