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
#include <linux/semaphore.h>
#include <linux/mvf_sema4.h>
#include <linux/interrupt.h>

// common to MQX and Linux
// TODO the order of these should not matter
#include "mcc_config.h"
#include "mcc_common.h"

// linux only
#include "mcc_linux.h"
#include "mcc_shm_linux.h"
#include "mcc_sema4_linux.h"

/*
 * This modules combines protection between cores using
 * mvf_sema4 routines with protection between multiple
 * Linux processes using kernel semaphores (not mutex
 * because they need to be tested under interrupt).
 *
 * Since MCC requires all of shared memory to be protected
 * because of caching limitations on the M4 core
 * the calling routines do not provide a gate number.
 *
 * No explicit init call is used. It is checked / done 
 * at grab time.
*/

#define TIME_PROTECT_US 10000000

// local mutex
DEFINE_SEMAPHORE(linux_mutex);

// platform semaphore handle
static MVF_SEMA4* sema4 = NULL;

int mcc_sema4_grab()
{
	int i;

	// inited yet?
	if(!sema4) {
		int ret = mvf_sema4_assign(MVF_SHMEM_SEMAPHORE_NUMBER, &sema4);
		if(ret)
			return ret;
	}

	// only 1 linux process at a time
	if(down_killable(&linux_mutex) == EINTR)
		return -EINTR;

	// no M4 interrupts while we're working
	for(i = 0; i<MAX_MVF_CPU_TO_CPU_INTERRUPTS; i++)
		disable_irq(MVF_INT_CPU_INT0 + i);

	return mvf_sema4_lock(sema4, TIME_PROTECT_US, true);
}

int mcc_sema4_release()
{
	int ret, i;

	if(!sema4)
		return -EINVAL;

	ret = mvf_sema4_unlock(sema4);

	for(i = 0; i<MAX_MVF_CPU_TO_CPU_INTERRUPTS; i++)
		enable_irq(MVF_INT_CPU_INT0 + i);

	// now that M4 has been released, release linux
	up(&linux_mutex);

	return ret;
}

int mcc_sema4_isr_grab()
{
	// inited yet?
	if(!sema4) {
		int ret = mvf_sema4_assign(MVF_SHMEM_SEMAPHORE_NUMBER, &sema4);
		if(ret)
			return ret;
	}

	// spin to grab it
	while(mvf_sema4_lock(sema4, 0, false)) {};

	return 0;
}

int mcc_sema4_isr_release()
{
	if(!sema4)
		return -EINVAL;

	return mvf_sema4_unlock(sema4);
}


