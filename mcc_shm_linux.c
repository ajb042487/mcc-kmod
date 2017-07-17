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
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/version.h>

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

struct gen_pool *shm_gen_pool;
struct mcc_bookeeping_struct *bookeeping_data = null;

static void print_signals(void) {
	int i,j;

	MCC_SIGNAL *signal;
	char *sig_type;

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
}

void print_bookeeping_data(void)
{

	printk(KERN_DEBUG "bookeeping_data= 0x%08x, VIRT_TO_MQX(bookeeping_data)= 0x%08x\n", bookeeping_data, VIRT_TO_MQX(bookeeping_data));
	if(!bookeeping_data)
		return;

	printk(KERN_DEBUG ".init_string = %s\n", bookeeping_data->init_string);
#if 0

	for(i=0; i<MCC_ATTR_MAX_RECEIVE_ENDPOINTS; i++)
	{
		printk(KERN_DEBUG "bookeeping_data->r_lists[%d](addr=0x%08x) .head= 0x%08x, .tail= 0x%08x\n",
			i, VIRT_TO_MQX(&bookeeping_data->r_lists[i]), bookeeping_data->r_lists[i].head, bookeeping_data->r_lists[i].tail);
	}

	printk(KERN_DEBUG "bookeeping_data->free_list .head= 0x%08x, .tail= 0x%08x\n", bookeeping_data->free_list.head, bookeeping_data->free_list.tail);
#endif
	print_signals();
#if 0

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

struct gen_pool *mcc_get_smem_pool(unsigned long base_address)
{
	struct device_node *node;
	struct platform_device *pdev;
	struct gen_pool *ocram_pool;
	char *path = "/soc/sram@00000000";

	sprintf(path + 10, "%08x", base_address);
	node = of_find_node_by_path(path);
	if (!node) {
		pr_warn("%s: failed to find ocram node at %s!\n", __func__, path);
		return ERR_PTR(-ENODEV);
	}

	pdev = of_find_device_by_node(node);
	of_node_put(node);
	if (!pdev) {
		pr_warn("%s: failed to find ocram device!\n", __func__);
		return ERR_PTR(-ENODEV);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,73)
	ocram_pool = gen_pool_get(&pdev->dev, NULL);
#else
	ocram_pool = dev_get_gen_pool(&pdev->dev);
#endif
	if (!ocram_pool) {
		pr_warn("%s: ocram pool unavailable!\n", __func__);
		return ERR_PTR(-ENODEV);
	}

	return ocram_pool;
}

int mcc_map_shared_memory(void)
{
	unsigned long alloc_virt_addr;
	unsigned long alloc_phys_addr;

	shm_gen_pool = mcc_get_smem_pool(SHARED_IRAM_START);
	if (IS_ERR(shm_gen_pool)) {
		shm_gen_pool = NULL;
		return PTR_ERR(shm_gen_pool);
	}

	alloc_virt_addr = gen_pool_alloc(shm_gen_pool, SHARED_IRAM_SIZE);
	if (!alloc_virt_addr) {
		pr_warn("%s: unable to alloc ocram!\n", __func__);
		return -ENOMEM;
	}

	/* Verify we got the address space we expect */
	alloc_phys_addr = gen_pool_virt_to_phys(shm_gen_pool, alloc_virt_addr);
	if (alloc_phys_addr != SHARED_IRAM_START) {
		pr_warn("%s: alloc ocram is not located at expected address!\n",
			__func__);
		gen_pool_free(shm_gen_pool, alloc_virt_addr, SHARED_IRAM_SIZE);
		return -ENOMEM;
	}

	bookeeping_data = (struct mcc_bookeeping_struct *)alloc_virt_addr;

	return MCC_SUCCESS;
}

int mcc_initialize_shared_mem(void)
{
	int i,j;
	int return_value = MCC_SUCCESS;
	char init_string[INIT_STRING_LEN];
	unsigned char *bkdata;

	// critical region for shared memory begins
	if (mcc_sema4_grab()) {
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

	for(i=0; i<MCC_NUM_CORES; i++)
	{
		for(j=0; j<MCC_MAX_OUTSTANDING_SIGNALS; j++)
		{
			bookeeping_data->signals_received[i][j].type = 11;
			bookeeping_data->signals_received[i][j].destination.core = 22;
			bookeeping_data->signals_received[i][j].destination.node = 33;
			bookeeping_data->signals_received[i][j].destination.port = 44;
		}
	}

	// critical region for shared memory ends
	mcc_sema4_release();

	return return_value;
}

void mcc_deinitialize_shared_mem(void)
{
	gen_pool_free(shm_gen_pool, (unsigned long)bookeeping_data, SHARED_IRAM_SIZE);
	bookeeping_data = NULL;
}
