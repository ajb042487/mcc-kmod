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
#include <linux/kernel.h>
#include <linux/slab.h>

// common to MQX and Linux
// TODO the order of these should not matter
#include "mcc_config.h"
#include "mcc_common.h"

// linux only
#include "mcc_linux.h"
#include "mcc_shm_linux.h"
#include "mcc_sema4_linux.h"

#define INIT_STRING_LEN (sizeof(bookeeping_data->init_string))
#define VERSION_STRING_LEN (sizeof(bookeeping_data->version_string))

struct mcc_bookeeping_struct *bookeeping_data = null;

void print_bookeeping_data(void)
{
#if 0
	int i,j;
	MCC_SIGNAL *signal;
	char *sig_type;
	char init_string[INIT_STRING_LEN + 1];

	printk(KERN_DEBUG "bookeeping_data= 0x%08x, VIRT_TO_MQX(bookeeping_data)= 0x%08x\n", bookeeping_data, VIRT_TO_MQX(bookeeping_data));
	if(!bookeeping_data)
		return;

	memcpy_fromio(init_string, bookeeping_data->init_string, INIT_STRING_LEN);
	init_string[INIT_STRING_LEN] = 0;
	printk(KERN_DEBUG ".init_string = %s\n", bookeeping_data->init_string);

	for(i=0; i<MCC_ATTR_MAX_RECEIVE_ENDPOINTS; i++)
	{
		printk(KERN_DEBUG "bookeeping_data->r_lists[%d](addr=0x%08x) .head= 0x%08x, .tail= 0x%08x\n",
			i, VIRT_TO_MQX(&bookeeping_data->r_lists[i]), bookeeping_data->r_lists[i].head, bookeeping_data->r_lists[i].tail);
	}

	printk(KERN_DEBUG "bookeeping_data->free_list .head= 0x%08x, .tail= 0x%08x\n", bookeeping_data->free_list.head, bookeeping_data->free_list.tail);
	for(i=0; i<MCC_NUM_CORES; i++)
	{
		printk(KERN_DEBUG "bookeeping_data->signal_queue_head[%d]= 0x%08x, ->signal_queue_tail[%d]= 0x%08x\n",
			i, bookeeping_data->signal_queue_head[i], i, bookeeping_data->signal_queue_tail[i]);

		for(j=0; j<MCC_MAX_OUTSTANDING_SIGNALS; j++)
		{
			signal = &bookeeping_data->signals_received[i][j];
			sig_type = signal->type == BUFFER_QUEUED ? "BUFFER_QUEUED" : (signal->type == BUFFER_FREED ? "BUFFER_FREED" : "unknow type");
			printk(KERN_DEBUG "&bookeeping_data->signals_received[core=%d][%d] .type= %s, .destination=[%d, %d, %d]\n",
				i, j, sig_type, signal->destination.core, signal->destination.node, signal->destination.port);
		}
	}

	for(i=0; i<MCC_ATTR_MAX_RECEIVE_ENDPOINTS; i++)
	{
		printk(KERN_DEBUG "bookeeping_data->endpoint_table[%d] .endpoint=[%d, %d, %d] .list= 0x%08x\n",
			i, bookeeping_data->endpoint_table[i].endpoint.core, bookeeping_data->endpoint_table[i].endpoint.node,
			bookeeping_data->endpoint_table[i].endpoint.port, VIRT_TO_MQX(bookeeping_data->endpoint_table[i].list));
	}

	for(i=0; i<MCC_ATTR_NUM_RECEIVE_BUFFERS; i++) {
		printk(KERN_DEBUG
		"bookeeping_data->r_buffers[%d](addr=0x%08x).next= 0x%08x data[0-10]: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x ",
			i, VIRT_TO_MQX(&bookeeping_data->r_buffers[i]), bookeeping_data->r_buffers[i].next,
			bookeeping_data->r_buffers[i].data[0], bookeeping_data->r_buffers[i].data[1], bookeeping_data->r_buffers[i].data[2],
			bookeeping_data->r_buffers[i].data[3], bookeeping_data->r_buffers[i].data[4], bookeeping_data->r_buffers[i].data[5],
			bookeeping_data->r_buffers[i].data[6], bookeeping_data->r_buffers[i].data[7], bookeeping_data->r_buffers[i].data[8],
			bookeeping_data->r_buffers[i].data[9]);
	}
#endif
}

int mcc_map_shared_memory(void)
{
	// map the real shared memory
	if(!bookeeping_data)
	{
		if (request_mem_region(SHARED_IRAM_START, SHARED_IRAM_SIZE, "mcc_shmem"))
		{
			bookeeping_data = ioremap_nocache(SHARED_IRAM_START, SHARED_IRAM_SIZE);
			if (!bookeeping_data)
			{
				printk(KERN_ERR "unable to map region\n");
				release_mem_region(SHARED_IRAM_START, SHARED_IRAM_SIZE);
				return -ENOMEM;
			}
		}
		else
		{
			printk(KERN_ERR "unable to reserve real shared memory region\n");
			return -ENOMEM;
		}
	}
	return MCC_SUCCESS;
}

int mcc_initialize_shared_mem(void)
{
	int i;
	int return_value = MCC_SUCCESS;
	char init_string[INIT_STRING_LEN];
	unsigned char *bkdata;

	// critical region for shared memory begins
	if(mcc_sema4_grab(MCC_SHMEM_SEMAPHORE_NUMBER))
	{
		mcc_deinitialize_shared_mem();
		return -EBUSY;
	}

	memcpy_fromio(init_string, bookeeping_data->init_string, INIT_STRING_LEN);

	/* Initialize the bookeeping structure */
	if(memcmp(init_string, MCC_INIT_STRING, INIT_STRING_LEN))
	{
		printk(KERN_DEBUG "at entry, bookeeping_data not initialized\n");

		// zero it all - no guarantee Linux or uboot didnt touch it before it was reserved
		bkdata = (unsigned char *)bookeeping_data;
		for(i=0; i<sizeof(struct mcc_bookeeping_struct); i++)
			bkdata[i] = 0;
		//memset(bookeeping_data, 0, sizeof(struct mcc_bookeeping_struct));

		// Now initialize all the non-zero items
		
		/* Set init_flag in case it has not been set yet by another core */
		//memcpy(bookeeping_data->init_string, MCC_INIT_STRING, INIT_STRING_LEN);
		memcpy_toio(bookeeping_data->init_string, MCC_INIT_STRING, INIT_STRING_LEN);

	    	/* Set version_string */
		memcpy_toio(bookeeping_data->version_string, MCC_VERSION_STRING, VERSION_STRING_LEN);

		/* Initialize the free list */
		bookeeping_data->free_list.head = (MCC_RECEIVE_BUFFER *)VIRT_TO_MQX(&bookeeping_data->r_buffers[0]);
		bookeeping_data->free_list.tail = (MCC_RECEIVE_BUFFER *)VIRT_TO_MQX(&bookeeping_data->r_buffers[MCC_ATTR_NUM_RECEIVE_BUFFERS-1]);

		/* Initialize receive buffers */
		for(i=0; i<MCC_ATTR_NUM_RECEIVE_BUFFERS-1; i++)
		{
			bookeeping_data->r_buffers[i].next = (MCC_RECEIVE_BUFFER *)VIRT_TO_MQX(&bookeeping_data->r_buffers[i+1]);
		}
		bookeeping_data->r_buffers[MCC_ATTR_NUM_RECEIVE_BUFFERS-1].next = null;
	}
	else
		printk(KERN_DEBUG "at entry, bookeeping_data was initialized\n");

	// critical region for shared memory ends
	mcc_sema4_release(MCC_SHMEM_SEMAPHORE_NUMBER);

	return return_value;
}

void mcc_deinitialize_shared_mem(void)
{
	if(bookeeping_data)
	{
		iounmap(bookeeping_data);
		release_mem_region(SHARED_IRAM_START, SHARED_IRAM_SIZE);
		bookeeping_data = null;
	}
}


