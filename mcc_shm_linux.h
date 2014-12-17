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
#ifndef __MCC_SHM_LINUX_H__
#define __MCC_SHM_LINUX_H__

extern struct mcc_bookeeping_struct *bookeeping_data;

#define VIRT_TO_MQX(a) ((a == 0) ? 0 : ((unsigned)(a) - (unsigned)bookeeping_data) + (unsigned)SHARED_IRAM_START)
#define MQX_TO_VIRT(a) ((a == 0) ? 0 : ((unsigned)(a) - SHARED_IRAM_START) + (unsigned)bookeeping_data)

int mcc_initialize_shared_mem(void);
void mcc_deinitialize_shared_mem(void);
void print_bookeeping_data(void);
int mcc_map_shared_memory(void);

#endif /* __MCC_SHM_LINUX_H__ */
