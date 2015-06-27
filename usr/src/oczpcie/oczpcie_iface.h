/*
 * oczpcie_iface.h
 *
 * Copyright 2007 Red Hat, Inc.
 * Copyright 2008 Marvell. <kewei@marvell.com>
 * Copyright 2009-2011 Marvell. <yuxiangl@marvell.com>
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

#ifndef OCZZD_IFACE_H_
#define OCZZD_IFACE_H_

#include	<linux/fs.h>
#include	"oczpcie_main.h"
#include	"defs.h"
#include	"vca_iface.h"

extern struct list_head card_list;
extern register_card_callback_t register_card_add_callback;
extern unregister_card_callback_t register_card_remove_callback;


int oczpcie_getgeo(struct block_device *bdev, struct hd_geometry *geo);
void oczpcie_make_request(struct oczpcie_prv_info *priv, int alloc_flags, struct bio *bio, int retries);
int oczpcie_issue_command(struct oczpcie_prv_info *mpi, int alloc_flags, struct oczpcie_issue_command *commnd_info);
void oczpcie_abort_issue_command(struct oczpcie_prv_info *mpi, struct oczpcie_issue_command *commnd_info);
int oczpcie_get_dev_id_from_block_device(struct block_device *bdev, struct oczpcie_info **oczi);
void oczpcie_reset_card(struct oczpcie_prv_info *priv);

#endif /* OCZZD_IFACE_H_ */
