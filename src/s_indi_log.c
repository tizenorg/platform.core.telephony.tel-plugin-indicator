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

#include <glib.h>

#include "s_indi_log.h"

#ifdef TCORE_LOG_TAG
#define LOG_TAG TCORE_LOG_TAG
#else
#define LOG_TAG "S_INDI"
#endif

const char *log_tag_name[MODEM_ID_LAST + 1] = {
	[MODEM_ID_PRIMARY] = LOG_TAG"/SUBS-0",
	[MODEM_ID_SECONDARY] = LOG_TAG"/SUBS-1"
};

const char *s_indi_get_log_tag_with_id(unsigned int modem_id)
{
	g_assert(modem_id <= MODEM_ID_SECONDARY);
	return log_tag_name[modem_id];
}

gchar *s_indi_get_log_tag_with_cp_name(const char *cp_name)
{
	return g_strdup_printf("%s/%s", LOG_TAG, cp_name);
}
