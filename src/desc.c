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

#include <tcore.h>
#include <plugin.h>

#include "s_indi_main.h"
#include "s_indi_util.h"

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION 1
#endif

static gboolean on_load()
{
	dbg("i'm load");
	return TRUE;
}

static gboolean on_init(TcorePlugin *plugin)
{
	gboolean result = FALSE;
	s_indi_assert(NULL != plugin);

	result = s_indi_init(plugin);
	if (result == FALSE)
		err("Failed intializing the plugin");
	else
		dbg("indicator-plugin INIT SUCCESS");

	return result;
}

static void on_unload(TcorePlugin *plugin)
{
	s_indi_assert(NULL != plugin);

	s_indi_deinit(plugin);
	dbg("indicator-plugin UNLOAD COMPLETE");
}

EXPORT_API struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "INDICATOR",
	.priority = TCORE_PLUGIN_PRIORITY_MID + 2,
	.version = PLUGIN_VERSION,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
