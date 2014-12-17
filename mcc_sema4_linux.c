/*
 * Copyright 2013 Freescale Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <linux/types.h>
#include <linux/device.h>
#include <mach/hardware.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/kernel.h>

// common to MQX and Linux
// TODO the order of these should not matter
#include "mcc_config.h"
#include "mcc_common.h"

// linux only
#include "mcc_linux.h"
#include "mcc_shm_linux.h"
#include "mcc_sema4_linux.h"

int mcc_sema4_grab(unsigned char gate_num)
{
	unsigned char gate_val;
	int timeout_ms;

	if((gate_num < 0) || (gate_num >= MAX_SEMA4_GATES))
		return -EINVAL;

	gate_val = MCC_CORE_NUMBER + 1;
	SEMA4_GATEn_WRITE(gate_val, gate_num);

	/*
	The expectation is that holds of the semaphore are really short
	so it's ok to treat them like a spin lock (with protection from
	real hangs of 1/2 second).
	*/

	timeout_ms = 10;	// 1/100 second
	while(timeout_ms && (gate_val != SEMA4_GATEn_READ(gate_num)))
	{
		udelay(1000);	// 1 milli-second
		SEMA4_GATEn_WRITE(gate_val, gate_num);
		timeout_ms--;
	}

	return timeout_ms > 0 ? MCC_SUCCESS : -EBUSY;
}

int mcc_sema4_release(unsigned char gate_num)
{

	if((gate_num < 0) || (gate_num >= MAX_SEMA4_GATES))
		return -EINVAL;

	SEMA4_GATEn_WRITE(0, gate_num);

	if(SEMA4_GATEn_READ(gate_num) == 0)
		return MCC_SUCCESS;
	else
		return -EIO;
}

