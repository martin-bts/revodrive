/*
 * vca_iface.h
 *
 * Copyright 2014 OCZ Storage Solutions. <http://ocz.com/enterprise/support>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifndef VCA_IFACE_H_
#define VCA_IFACE_H_

#include	<linux/fs.h>
#include	"oczpcie_main.h"

typedef void (*register_card_callback_t)(struct oczpcie_prv_info *priv, int num_devices,
		int domain_number, int bus_number, int bus_secondary);
typedef void (*unregister_card_callback_t)(struct oczpcie_prv_info *priv);

// Ask to be called back when a new card is detected, pass NULL as the callback to prevent new callbacks
void oczpcie_vca_register_card_add_callback(register_card_callback_t card_callback);
// Ask to be called when a card is removed, pass NULL as the callback to prevent new callbacks
void oczpcie_vca_register_card_remove_callback(unregister_card_callback_t card_callback);
// Make a request to one of our devices (only)
void oczpcie_vca_make_request(struct oczpcie_prv_info *priv, struct bio *bio);
// Open one of our devices, this allocates and returns the block_device structure
int oczpcie_vca_get_bdev(struct oczpcie_prv_info *priv, int device_id, struct block_device **device);
// Close a device, this will free the structure
void oczpcie_vca_put_bdev(struct oczpcie_prv_info *priv, struct block_device *bdev);
// Issue a direct command to the device
int oczpcie_vca_issue_command(struct oczpcie_prv_info *priv, struct oczpcie_issue_command *command_info);
// Abort a command issue
void oczpcie_vca_abort_issue_command(struct oczpcie_prv_info *priv , struct oczpcie_issue_command *command_info);
// read BIOS information
int oczpcie_vca_read_bios(struct oczpcie_prv_info *priv, int address, void *buffer, int len);

#endif /* VCA_IFACE_H_ */
