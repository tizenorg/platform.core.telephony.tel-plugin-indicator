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

#include <tcore.h>

enum {
	MODEM_ID_PRIMARY,
	MODEM_ID_SECONDARY
};

#define MODEM_ID_FIRST  MODEM_ID_PRIMARY
#define MODEM_ID_LAST  MODEM_ID_SECONDARY

#ifdef FEATURE_LOG_MODE_VERBOSE
#define s_indi_log_v(...) dbg(__VA_ARGS__)
#else
#define s_indi_log_v(...) \
	do { \
	} while (0);
#endif

#ifdef FEATURE_LOG_TX_RX_DATA
#define s_indi_log_txrx(id,...) \
	do { \
		const char *tag = s_indi_get_log_tag_with_id(id); \
		info_ex(tag, __VA_ARGS__); \
	} while (0);
#else
#define s_indi_log_txrx(id,...) \
	do { \
	} while (0);
#endif

#define s_indi_log_ex(name,...) \
	do { \
		gchar *tag = s_indi_get_log_tag_with_cp_name(name); \
		dbg_ex(tag, __VA_ARGS__); \
		g_free(tag); \
	} while (0);

inline const char *s_indi_get_log_tag_with_id(unsigned int modem_id);
inline char *s_indi_get_log_tag_with_cp_name(const char *cp_name);
