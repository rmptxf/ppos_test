/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _AGGREGATOR_H_
#define _AGGREGATOR_H_

#include <zephyr/types.h>

#define ENTRY_MAX_SIZE 20
#define FIFO_MAX_ELEMENT_COUNT 12

struct reader_data {
	uint8_t length;
	uint8_t data[ENTRY_MAX_SIZE];
};

int aggregator_init(void);

int aggregator_put(struct reader_data data);

int aggregator_get(struct reader_data *data);

void aggregator_clear(void);

int aggregator_element_count_get(void);

#endif /* _AGGREGATOR_H_ */
