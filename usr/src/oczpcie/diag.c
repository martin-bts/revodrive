/*
 * diag.c
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

#include	<linux/ata.h>
#include	<linux/workqueue.h>
#include	"oczpcie_main.h"
#include	"defs.h"
#include	"util.h"
#include	"chip.h"
#include	"oczpcie_iface.h"

struct error_work_entry {
	struct work_struct work_entry;	// NB MUST be first in structure so has same address
	struct oczpcie_info *oczi;
	struct oczpcie_device *device;
};

static const char *const err0_meaning[32] = {
		"Buffer parity error",	// 0
		"Watchdog timeout",	// 1
		"Credit timeout",	// 2
		"Invalid destination", // 3
		"Unsupported connection rate", // 4
		"Invalid protocol",	// 5
		"Bad destination", // 6
		"Break received",	// 7
		"STP busy",	// 8
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 9 - 21
		"TX Stopped early", // 22
		"SATA R_ERR primitive", // 23
		"SATA error",	// 24
		NULL, NULL,
		"Unknown FIS",	// 27
		"FIS retry limit exceeded", // 28
		"Response buffer overflow", // 29
		"Protection info error", // 30
		"Command issue stopped",	// 31
};

static void diag_decode(u32 err, const char *const msg[])
{
	int bit, previous;
	char buffer[256];

	buffer[0] = '\000';

	previous = 0;
	for (bit = 0; bit < 32; bit++) {
		if (err & (1 << bit)) {
			if (msg[bit]) {
				if (previous) {
					strcat(buffer, " | ");
				}
				else {
					strcat(buffer, " { ");
				}
				strcat(buffer, msg[bit]);
				previous = 1;
			}
		}
	}
	if (previous)
		strcat(buffer, " }");

	strcat(buffer, "\n");

	printk(KERN_ERR "%s", buffer);
}


void oczpcie_diag_decode_err0(struct oczpcie_info *oczi, struct oczpcie_task *task, u32 slot, u32 err0, u32 err1)
{
	if (printk_ratelimit()) {
		dev_printk(KERN_ERR, oczi->dev, "Error on device %d for slot 0x%x, command 0x%x, lba %lld: ", calc_device(oczi, task->device_number), slot, task->ata_task.fis.command, task->lba);
		printk(KERN_ERR "error code 0x%08x:0x%08x", err0, err1);
		diag_decode(err0, err0_meaning);
	}
}

void oczpcie_diag_sata_error(struct oczpcie_info *oczi, struct oczpcie_task *task, struct oczpcie_dev_to_host_fis *fis)
{
	if (task->ata_task.use_ncq == 0 && printk_ratelimit()) {	// don't report for NCQ errors, these are handled separately
		size_t lba = fis->lbal;
		lba |= ((u64)fis->lbam << 8);
		lba |= ((u64)fis->lbah << 16);
		lba |= ((u64)fis->lbal_exp << 24);
		lba |= ((u64)fis->lbam_exp << 32);
		lba |= ((u64)fis->lbah_exp << 40);
		dev_printk(KERN_ERR, oczi->dev, "SATA device information: Device %d, Error 0x%x, status  0x%x, lba %zd\n", calc_device(oczi, task->device_number), fis->error, fis->status, lba);
	}
}

static void abort_all_commands(struct oczpcie_prv_info *priv)
{
	int host, device, tag;

	for (host = 0; host < N_HOST; host++) {
		struct oczpcie_info *oczi = priv->oczi[host];
		for (device = 0; device < N_PHY; device++) {
			for (tag = 0; tag < MAX_NCQ_DEPTH; tag++) {
				oczpcie_slot_complete(oczi, calc_slot(device, tag) | RXQ_ERR | RXQ_SLOT_RESET);
			}
		}
	}
}

static void retune_all_phys(struct oczpcie_prv_info *priv)
{
	int host, device;

	for (host = 0; host < N_HOST; host++) {
		struct oczpcie_info *oczi = priv->oczi[host];
		for (device = 0; device < N_PHY; device++) {
			chip_phy_reset(oczi, device, OCZPCIE_PHY_TUNE);
		}
	}
}

#define	MAX_WAIT	50
static void oczpcie_diag_read_log(struct oczpcie_info *oczi, struct oczpcie_device *device, int gfp_flags)
{
	struct oczpcie_issue_command command_info;
	int log_wait;
	int i;
	unsigned long flags = 0;

	// abort all commands on device
	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_lock_bh(&oczi->lock);
	else
		spin_lock_irqsave(&oczi->lock, flags);
	for (i = 0; i < MAX_NCQ_DEPTH; i++) {
		if (device->timeout[i]) {
			oczpcie_slot_complete(oczi, calc_slot(device->device_id, i) | RXQ_ERR | RXQ_SLOT_RESET);
		}
	}
	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_unlock_bh(&oczi->lock);
	else
		spin_unlock_irqrestore(&oczi->lock, flags);

	// read log
	memset(&command_info, 0, sizeof(command_info));

	command_info.process_flags = no_queue;
	command_info.cmd = ATA_CMD_READ_LOG_EXT;
	command_info.lba = ATA_LOG_SATA_NCQ | (0x10 << 8);	// want page 0x10
	command_info.dev_id = device->device_id;
	if (oczi->id > 0)
		command_info.dev_id += oczi->n_phy;
	command_info.len = 512;
	command_info.use_dma = 1;
	sema_init(&command_info.sem, 0);

	command_info.num_pages = alloc_seperate_pages(command_info.len, &command_info.data, gfp_flags);
	if (unlikely(command_info.num_pages < 1)) {
		oczpcie_printk("Not enough memory to handle NCQ error\n");
		return;
	}

	if (unlikely(oczpcie_issue_command(oczi->prv_info, gfp_flags, &command_info))) {
		oczpcie_printk("Failed to read log for NCQ error\n");
		goto free_pages;
	}
	log_wait = 0;
	while (down_trylock(&command_info.sem) && log_wait++ < MAX_WAIT) {
		// we don't want to wait forever, so try with a sleep
		msleep(100);
	}
	oczpcie_abort_issue_command(oczi->prv_info, &command_info);
	if (log_wait >= MAX_WAIT) {
		struct oczpcie_prv_info *priv = oczi->prv_info;

		dev_printk(KERN_ERR, oczi->dev, "Read log timeout on device %d\n", calc_device(oczi, device->device_id));
		if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
				spin_lock_bh(&oczi->lock);
		else
				spin_lock_irqsave(&oczi->lock, flags);
		oczi->prv_info->prv_flags |= PRV_FLAGS_CONTROLLER_PAUSED;       // don't allow any new commands
		printk("Begin card recovery\n");
		abort_all_commands(oczi->prv_info);     // abort everything
		if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
				spin_unlock_bh(&oczi->lock);
		else
				spin_unlock_irqrestore(&oczi->lock, flags);

		retune_all_phys(oczi->prv_info); // drop the links to flush the data

		oczpcie_reset_card(oczi->prv_info);
		printk("End card recovery\n");

		oczi->prv_info->prv_flags &= ~PRV_FLAGS_CONTROLLER_PAUSED;       // don't allow any new commands
	}

//	dev_printk(KERN_ERR, oczi->dev, "NCQ Error tag %d\n", *(u8 *)page_address(command_info.data[0]) & 0x1f);

free_pages:
	free_seperate_pages(command_info.data, command_info.num_pages);
}

static void delayed_ncq_error_handler(struct work_struct *work)
{
	struct error_work_entry *error_work_entry = (struct error_work_entry *)work;
	struct oczpcie_info *oczi = error_work_entry->oczi;
	struct oczpcie_device *device = error_work_entry->device;
	int i;
	unsigned long flags = 0;

	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_lock_bh(&oczi->lock);
	else
		spin_lock_irqsave(&oczi->lock, flags);
	if (device->dev_status == OCZPCIE_DEV_EH) {
		struct oczpcie_task *queue_task;

		if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_unlock_bh(&oczi->lock);
		else
			spin_unlock_irqrestore(&oczi->lock, flags);
		oczpcie_diag_read_log(oczi, device, GFP_NOIO);
		if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_lock_bh(&oczi->lock);
		else
			spin_lock_irqsave(&oczi->lock, flags);
		device->dev_status = OCZPCIE_DEV_NORMAL;

		for (i = 0; i < MAX_NCQ_DEPTH; i++) {
			if (list_empty(&oczi->task_queue[device->device_id])) {
				break;
			}
			queue_task = list_first_entry(&oczi->task_queue[device->device_id], struct oczpcie_task, list);
			// if we manage to send it to the card, remove it from the queue
			if (oczpcie_queue_command(queue_task, queue_task->oczi) == 0) {
				list_del(&queue_task->list);
			}
			else {
				break;
			}
		}
	}
	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_unlock_bh(&oczi->lock);
	else
		spin_unlock_irqrestore(&oczi->lock, flags);
	kfree(work);
}

void oczpcie_diag_handle_ncq_error(struct oczpcie_info *oczi, struct oczpcie_device *device)
{
	struct error_work_entry *error_work_entry = kmalloc(sizeof(struct error_work_entry), GFP_ATOMIC);

	if (unlikely(error_work_entry == NULL))
			return;

	INIT_WORK(&error_work_entry->work_entry, delayed_ncq_error_handler);
	error_work_entry->oczi = oczi;
	error_work_entry->device = device;
	queue_work(oczi->prv_info->error_workqueue, &error_work_entry->work_entry);
}
