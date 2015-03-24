CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(indicator-plugin C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(LIBDIR ${LIB_INSTALL_DIR})

### Set required packages ###
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 dlog deviced tcore vconf)

FOREACH(flag ${pkgs_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

### Plugin name/destination ###
SET(PLUGIN_NAME "indicator-plugin")
SET(PLUGIN_DEST "${LIB_INSTALL_DIR}/telephony/plugins")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -O2 -Werror -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wredundant-decls -Wcast-align -Wall -Wno-array-bounds -Wno-empty-body -Wno-ignored-qualifiers -Wswitch-default -Wno-unused-but-set-parameter -Wno-unused-but-set-variable")

### Common definitions ###
ADD_DEFINITIONS("-DFEATURE_TLOG_DEBUG")
#ADD_DEFINITIONS("-DFEATURE_LOG_MODE_VERBOSE")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"INDICATOR\"")
ADD_DEFINITIONS("-DPLUGIN_VERSION=${VERSION}")
ADD_DEFINITIONS("-DEXPORT_API=__attribute__((visibility(\"default\")))")

INCLUDE_DIRECTORIES(
   ${CMAKE_SOURCE_DIR}/include
)

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${pkgs_LDFLAGS})

SET(PROFILE_DEFINITIONS
	#ENABLE_AT_FACTORY_IPC
	FEATURE_LOG_TX_RX_DATA
)

SET(SRCS
    src/desc.c
    src/s_indi_main.c
    src/s_indi_log.c
)

# library build
ADD_LIBRARY(indicator-plugin SHARED ${SRCS})
TARGET_LINK_LIBRARIES(indicator-plugin ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(indicator-plugin 
		PROPERTIES PREFIX "" 
		OUTPUT_NAME indicator-plugin
		LINKER_LANGUAGE C
		COMPILE_DEFINITIONS "${PROFILE_DEFINITIONS}")
# install
INSTALL(TARGETS ${PLUGIN_NAME} LIBRARY DESTINATION ${PLUGIN_DEST})
INSTALL(TARGETS indicator-plugin LIBRARY DESTINATION ${LIBDIR}/telephony/plugins)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-indicator)
