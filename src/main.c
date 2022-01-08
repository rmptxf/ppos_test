/*
 * Copyright (c) 2018 Linaro Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include "protocol.h"

#include <net/net_config.h>
#include <net/net_event.h>

#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_key_mgmt.h>

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
#include <logging/log.h>

LOG_MODULE_REGISTER(ppos_gateway_app, LOG_LEVEL_INF);

/* This comes from newlib. */
#include <inttypes.h>

void main(void)
{
	int err;

	LOG_INF("ppos application started");

	err = nrf_modem_lib_init(NORMAL_MODE);
	if (err) {
		LOG_ERR("Failed to initialize modem library!, err: [%d] %s", err, strerror(-err));
		return;
	}

	LOG_INF("waiting for network.. ");
	err = lte_lc_init_and_connect();
	if (err) {
		LOG_ERR("Failed to connect to the LTE network, err: [%d] %s", err, strerror(-err));
		return;
	}
	LOG_INF("network connected!");

	mqtt_startup(CONFIG_CLOUD_BROKER_HOSTNAME, CONFIG_CLOUD_BROKER_PORT);

}