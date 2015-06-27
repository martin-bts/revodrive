/*
 * oczpcie_main.c
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

#include	"oczpcie_main.h"
#include	"chip.h"
#include	"diag.h"

void oczpcie_tag_clear(struct oczpcie_device *device, u32 tag)
{
	void *bitmap = &device->tags;
	clear_bit(tag, bitmap);
	device->flags &= ~RUNNING_NON_NCQ;
}

void oczpcie_tag_free(struct oczpcie_device *device, u32 tag)
{
	oczpcie_tag_clear(device, tag);
}

void oczpcie_tag_set(struct oczpcie_device *device, unsigned int tag)
{
	void *bitmap = &device->tags;
	set_bit(tag, bitmap);
}

inline int oczpcie_tag_alloc(struct oczpcie_device *device, u32 *tag_out, int is_non_ncq)
{
	unsigned int index, tag;
	void *bitmap = &device->tags;
	u32 bits = *(u64 *)bitmap;

	if (unlikely(device->flags & RUNNING_NON_NCQ))
		return -OCZPCIE_QUEUE_FULL;
	if (unlikely(is_non_ncq) && bits != 0) {
		return -OCZPCIE_QUEUE_FULL;
	}
	index = find_first_zero_bit(bitmap, device->tags_num);
	tag = index;
	if (tag >= device->tags_num)
		return -OCZPCIE_QUEUE_FULL;
	oczpcie_tag_set(device, tag);
	if (unlikely(is_non_ncq)) {
		device->flags |= RUNNING_NON_NCQ;
	}
	*tag_out = tag;
	return 0;
}

void oczpcie_tag_init(struct oczpcie_device *device)
{
	int i;
	for (i = 0; i < device->tags_num; ++i)
		oczpcie_tag_clear(device, i);
}

struct oczpcie_device *oczpcie_find_dev_by_reg_set(struct oczpcie_info *oczi,
						u8 reg_set)
{
	u32 dev_no;
	for (dev_no = 0; dev_no < N_PHY; dev_no++) {
		if (oczi->devices[dev_no].taskfileset == OCZPCIE_ID_NOT_MAPPED)
			continue;

		if (oczi->devices[dev_no].taskfileset == reg_set)
			return &oczi->devices[dev_no];
	}
	return NULL;
}

static inline void oczpcie_free_reg_set(struct oczpcie_info *oczi,
				struct oczpcie_device *dev)
{
	if (!dev) {
		oczpcie_printk("device has been free.\n");
		return;
	}
	if (dev->taskfileset == OCZPCIE_ID_NOT_MAPPED)
		return;
	chip_free_reg_set(oczi, &dev->taskfileset);
}

static inline u8 oczpcie_assign_reg_set(struct oczpcie_info *oczi,
				struct oczpcie_device *dev)
{
	if (dev->taskfileset != OCZPCIE_ID_NOT_MAPPED)
		return 0;
	return chip_assign_reg_set(oczi, &dev->taskfileset);
}

void oczpcie_set_sas_addr(struct oczpcie_info *oczi, int port_id,
				u32 off_lo, u32 off_hi, u64 sas_addr)
{
	u32 lo = (u32)sas_addr;
	u32 hi = (u32)(sas_addr>>32);

	oczpcie_write_port_cfg_addr(oczi, port_id, off_lo);
	oczpcie_write_port_cfg_data(oczi, port_id, lo);
	oczpcie_write_port_cfg_addr(oczi, port_id, off_hi);
	oczpcie_write_port_cfg_data(oczi, port_id, hi);
}

static int oczpcie_task_prep_ata(struct oczpcie_info *oczi,
			     struct oczpcie_task_exec_info *tei, u32 phy_id)
{
	struct oczpcie_task *task = tei->task;
	struct oczpcie_cmd_hdr *hdr = tei->hdr;
	struct oczpcie_slot_info *slot;
	void *buf_prd;
	u32 tag = tei->tag, hdr_tag;
	u32 flags, del_q;
	void *buf_tmp;
	u8 *buf_cmd, *buf_oaf;
	dma_addr_t buf_tmp_dma;
	u32 i, req_len, resp_len, slot_number;
	const u32 max_resp_len = SB_RFB_MAX;

	slot_number = calc_slot(task->device_number, tag);
	slot = &oczi->slot_info[slot_number];
	slot->tx = oczi->tx_prod;
	del_q = TXQ_MODE_I | slot_number |
		(TXQ_CMD_STP << TXQ_CMD_SHIFT) |
		((1 << phy_id) << TXQ_PHY_SHIFT) |
		((phy_id) << TXQ_SRS_SHIFT);
	oczi->tx[oczi->tx_prod] = cpu_to_le32(del_q);

	flags = (tei->n_elem << MCH_PRD_LEN_SHIFT);

	if (task->ata_task.use_ncq)
		flags |= MCH_FPDMA;

	if (unlikely(task->ata_task.fis.control & ATA_SRST))
		flags |= MCH_RESET;

	hdr->flags = cpu_to_le32(flags);

	if (task->ata_task.use_ncq )
		task->ata_task.fis.sector_count |= (u8) (tag << 3);
	else
		hdr_tag = tag;

	hdr->tags = cpu_to_le32(tag);

	hdr->data_len = cpu_to_le32(task->total_xfer_len);

	/* command table */
	buf_cmd = buf_tmp = slot->buf;
	buf_tmp_dma = slot->buf_dma;

	hdr->cmd_tbl = cpu_to_le64(buf_tmp_dma);

	buf_tmp += OCZPCIE_ATA_CMD_SZ;
	buf_tmp_dma += OCZPCIE_ATA_CMD_SZ;

	/* Open Address Frame, not really used for SATA */
	buf_oaf = buf_tmp;
	hdr->open_frame = cpu_to_le64(buf_tmp_dma);

	buf_tmp += OCZPCIE_OAF_SZ;
	buf_tmp_dma += OCZPCIE_OAF_SZ;

	/* PRD */
	buf_prd = buf_tmp;

	if (tei->n_elem)
		hdr->prd_tbl = cpu_to_le64(buf_tmp_dma);
	else
		hdr->prd_tbl = 0;
	i = oczpcie_get_prd_size() * oczpcie_get_prd_count();

	buf_tmp += i;
	buf_tmp_dma += i;

	/* Status buffer */
	slot->response = buf_tmp;
	hdr->status_buf = cpu_to_le64(buf_tmp_dma);

	req_len = sizeof(struct oczpcie_host_to_dev_fis);
	resp_len = OCZPCIE_SLOT_BUF_SZ - OCZPCIE_ATA_CMD_SZ -
	    sizeof(struct oczpcie_err_info) - i;

	/* request, response lengths */
	resp_len = min(resp_len, max_resp_len);
	hdr->lens = cpu_to_le32(((resp_len / 4) << 16) | (req_len / 4));

	if (likely(!task->ata_task.device_control_reg_update))
		task->ata_task.fis.flags |= 0x80;
	/* copy in FIS */
	memcpy(buf_cmd, &task->ata_task.fis, sizeof(struct oczpcie_host_to_dev_fis));
#ifdef	OCZPCIE_DEBUG
	oczpcie_dprintk("Phy id %d\n", phy_id);
	{
		int i;
		for (i = 0; i < sizeof(struct oczpcie_host_to_dev_fis); i++) {
			printk("%02x ", buf_cmd[i]);
		}
			oczpcie_printk("\n");
	}
#endif

	/* generate open address frame hdr (first 12 bytes) */
	/* initiator, STP, ftype 1h */
	buf_oaf[0] = (1 << 7) | (PROTOCOL_STP << 4) | 0x1;
	buf_oaf[1] = LINK_RATE_6_0_GBPS & 0xf;
	*(u16 *)(buf_oaf + 2) = cpu_to_be16(phy_id + 1);
	memset(buf_oaf + 4, 0, SAS_ADDR_SIZE);

	/* fill in PRD */
	chip_make_prd(task->scatter, tei->n_elem, buf_prd);

	return 0;
}

#define	DEV_IS_GONE(mvi_dev)	((!mvi_dev || (mvi_dev->dev_type == NO_DEVICE)))
static int oczpcie_task_prep(struct oczpcie_task *task, struct oczpcie_info *oczi, int is_tmf, int *pass)
{
	struct oczpcie_task_exec_info tei;
	struct oczpcie_slot_info *slot;
	u32 tag = 0xdeadbeef, n_elem = 0, slot_number;
	int rc = 0;


    if (unlikely(oczi->prv_info->prv_flags & PRV_FLAGS_CONTROLLER_PAUSED)) {
            rc = -EINVAL;
            goto err_out;
    }

	if (unlikely(is_tmf && task->ata_task.use_ncq)) {
			oczpcie_printk(KERN_ERR "Cannot process tmf task with NCQ\n");
			rc = -EINVAL;
			goto err_out;
	}
	if (unlikely(oczi->devices[task->device_number].dev_status == OCZPCIE_DEV_EH && !is_tmf)) {
		rc = -EINVAL;
		goto err_out;
	}

	if (unlikely(is_tmf)) {
		rc = oczpcie_tag_alloc(&oczi->devices[task->device_number], &tag, 0);	// don't care about blocking other commands
		if (rc) {
			struct oczpcie_slot_info *slot;
			int slot_idx;

			tag = 0;
			slot_idx = calc_slot(task->device_number, tag);
			slot = &oczi->slot_info[slot_idx];
			// Need to make sure we have a tag, we are doing recovery anyway
			oczpcie_slot_complete(oczi,  slot_idx | RXQ_ERR);
		}
	}
	else {
		if (unlikely(task->retry_count == 0)) {
			// convert NCQ commands to non-NCQ to try to get better diagnostics
			if (task->ata_task.fis.command == ATA_CMD_FPDMA_READ) {
				task->ata_task.use_ncq = 0;
				task->ata_task.fis.command = ATA_CMD_READ;
				task->ata_task.fis.sector_count = task->ata_task.fis.features;
				task->ata_task.fis.sector_count_exp = task->ata_task.fis.features_exp;
				task->ata_task.fis.features = task->ata_task.fis.features_exp = 0;
			}
			else if (task->ata_task.fis.command == ATA_CMD_FPDMA_WRITE) {
				task->ata_task.use_ncq = 0;
				task->ata_task.fis.command = ATA_CMD_WRITE;
				task->ata_task.fis.sector_count = task->ata_task.fis.features;
				task->ata_task.fis.sector_count_exp = task->ata_task.fis.features_exp;
				task->ata_task.fis.features = task->ata_task.fis.features_exp = 0;
			}
		}
		rc = oczpcie_tag_alloc(&oczi->devices[task->device_number], &tag, !task->ata_task.use_ncq);
	}

	if (rc) {
		goto err_out;
	}

	if (task->num_scatter) {
		n_elem = dma_map_sg(oczi->dev,
					task->scatter,
					task->num_scatter,
					task->data_dir);
		if (!n_elem) {
			rc = -ENOMEM;
			goto prep_out;
		}
	}

	if (likely(	task->ata_task.use_ncq))
		task->ata_task.fis.sector_count = tag << 3;

	slot_number = calc_slot(task->device_number, tag);
	slot = &oczi->slot_info[slot_number];

	task->slot = NULL;
	slot->n_elem = n_elem;
	slot->slot_tag = tag;
	slot->device = &oczi->devices[task->phy_id];

	memset(slot->buf, 0, OCZPCIE_SLOT_BUF_SZ);

	tei.task = task;
	tei.hdr = &oczi->slot[slot_number];
	tei.tag = tag;
	tei.n_elem = n_elem;
	rc = oczpcie_task_prep_ata(oczi, &tei, task->phy_id);
	if (rc) {
		oczpcie_dprintk("rc is %x\n", rc);
		goto err_out_tag;
	}
	slot->task = task;
	task->slot = slot;

//	mvi_dev->running_req++;
	++(*pass);
	oczi->tx_prod = (oczi->tx_prod + 1) & (OCZPCIE_CHIP_SLOT_SZ - 1);

	return rc;

err_out_tag:
	oczpcie_tag_free(&oczi->devices[task->device_number], tag);
err_out:

	//dev_printk(KERN_ERR, oczi->dev, "oczpcie prep failed[%d]!\n", rc);
	if (n_elem)
		dma_unmap_sg(oczi->dev, task->scatter, n_elem,
				 task->data_dir);
prep_out:
	return rc;
}

// caller needs to have oczi->lock before calling
int oczpcie_task_exec(struct oczpcie_task *task, int is_tmf, struct oczpcie_info *oczi)
{
	u32 rc = 0;
	u32 pass = 0;

	rc = oczpcie_task_prep(task, oczi, is_tmf, &pass);
	if (rc) {
		//dev_printk(KERN_ERR, oczi->dev, "oczpcie exec failed[%d]!\n", rc);
		return rc;
	}
	if (likely(pass)) {
		oczi->timeout[task->device_number] = jiffies + (task->timeout ? task->timeout : DEFAULT_TIMEOUT);
		if (unlikely(oczi->timeout[task->device_number]) == 0)
			oczi->timeout[task->device_number] = 1;	// avoid 0, means timeout is not active
		oczi->devices[task->device_number].timeout[task->slot->slot_tag] = oczi->timeout[task->device_number];	// Set per-command timeout
		oczpcie_start_delivery(oczi, (oczi->tx_prod - 1) &
			(OCZPCIE_CHIP_SLOT_SZ - 1));
	}

	return rc;
}

int oczpcie_queue_command(struct oczpcie_task *task, struct oczpcie_info *oczi)
{
	return oczpcie_task_exec(task, 0, oczi);
}

static void oczpcie_slot_free(struct oczpcie_device *device, u32 rx_desc)
{
	u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
	oczpcie_tag_clear(device, slot_idx & NCQ_MASK);
}

static void oczpcie_slot_task_free(struct oczpcie_info *oczi, struct oczpcie_task *task,
			  struct oczpcie_slot_info *slot, u32 slot_idx)
{
	if (!slot->task)
		return;
	if (slot->n_elem)
		dma_unmap_sg(oczi->dev, task->scatter,
				 slot->n_elem, task->data_dir);
	if (task->scatter) {
		kfree(task->scatter);
		task->scatter = NULL;
	}
	// list_del_init(&slot->entry);	// FIXME
	task->slot = NULL;
	slot->task = NULL;
	slot->port = NULL;
	slot->slot_tag = 0xFFFFFFFF;
	oczpcie_slot_free(&oczi->devices[task->device_number], slot_idx);
}

static u32 oczpcie_is_phy_ready(struct oczpcie_info *oczi, int i)
{
	u32 tmp;
	struct oczpcie_phy *phy = &oczi->phy[i];

	tmp = oczpcie_read_phy_ctl(oczi, i);
	if ((tmp & PHY_READY_MASK) && !(phy->irq_status & PHYEV_POOF)) {
		oczi->phymap[oczi->phys_ready++] = i;
		phy->phy_attached = 1;
		return tmp;
	}

	return 0;
}

static u32 oczpcie_is_sig_fis_received(u32 irq_status)
{
	return irq_status & PHYEV_SIG_FIS;
}

static void oczpcie_sig_remove_timer(struct oczpcie_phy *phy)
{
	if (phy->timer.function)
		del_timer(&phy->timer);
	phy->timer.function = NULL;
}

void oczpcie_update_phyinfo(struct oczpcie_info *oczi, int i, int get_st)
{
	struct oczpcie_phy *phy = &oczi->phy[i];

	if (get_st) {
		phy->irq_status = oczpcie_read_port_irq_stat(oczi, i);
		phy->phy_status = oczpcie_is_phy_ready(oczi, i);
	}

	if (phy->phy_status) {
		chip_fix_phy_info(oczi, i);
		if (phy->phy_type & PORT_TYPE_SATA) {
			if (oczpcie_is_sig_fis_received(phy->irq_status)) {
				oczpcie_sig_remove_timer(phy);
				phy->phy_attached = 1;
				phy->att_dev_sas_addr =
					i + oczi->id * N_PHY;
				phy->frame_rcvd_size =
				    sizeof(struct oczpcie_host_to_dev_fis);
			} else {
				u32 tmp;
				dev_printk(KERN_DEBUG, oczi->dev,
					"Phy%d : No sig fis\n", i);
				tmp = oczpcie_read_port_irq_mask(oczi, i);
				oczpcie_write_port_irq_mask(oczi, i,
						tmp | PHYEV_SIG_FIS);
				phy->phy_attached = 0;
				phy->phy_type &= ~PORT_TYPE_SATA;
				goto out_done;
			}
		}	else if (phy->phy_type & PORT_TYPE_SAS
			|| phy->att_dev_info & PORT_SSP_INIT_MASK) {
			BUG_ON(1);
		}
	}
	oczpcie_dprintk("phy %d attach dev info is %x\n",
		i + oczi->id * N_PHY, phy->att_dev_info);
	oczpcie_dprintk("phy %d attach sas addr is %llx\n",
		i + oczi->id * N_PHY, phy->att_dev_sas_addr);
out_done:
	if (get_st)
		oczpcie_write_port_irq_stat(oczi, i, phy->irq_status);
}

struct oczpcie_device *oczpcie_alloc_dev(struct oczpcie_info *oczi)
{
	u32 dev;
	for (dev = 0; dev < N_PHY; dev++) {
		if (oczi->devices[dev].dev_type == NO_DEVICE) {
			oczi->devices[dev].device_id = dev;
			return &oczi->devices[dev];
		}
	}

	if (dev == N_PHY)
		oczpcie_printk("max support %d devices, ignore ..\n",
			OCZPCIE_MAX_DEVICES);

	return NULL;
}

#if 0
void oczpcie_free_dev(struct oczpcie_device *mvi_dev)
{
	u32 id = mvi_dev->device_id;
	memset(mvi_dev, 0, sizeof(*mvi_dev));
	mvi_dev->device_id = id;
	mvi_dev->dev_type = NO_DEVICE;
	mvi_dev->dev_status = OCZPCIE_DEV_NORMAL;
	mvi_dev->taskfileset = OCZPCIE_ID_NOT_MAPPED;
}
#endif

static int oczpcie_sata_done(struct oczpcie_info *oczi, struct oczpcie_task *task,
			u32 slot_idx, int err)
{
	struct task_status_struct *tstat = &task->task_status;
	struct ata_task_resp *resp = (struct ata_task_resp *)tstat->buf;
	int stat = OCZPCIE_SAM_STAT_GOOD;


	resp->frame_len = sizeof(struct oczpcie_dev_to_host_fis);
	memcpy(&resp->ending_fis[0],
	       SATA_RECEIVED_D2H_FIS(task->phy_id),
	       sizeof(struct oczpcie_dev_to_host_fis)); // phy_id is the register set we are using
	tstat->buf_valid_size = sizeof(*resp);
	if (unlikely(err)) {
		if (unlikely(err & CMD_ISS_STPD))
			stat = OCZPCIE_OPEN_REJECT;
		else
			stat = OCZPCIE_PROTO_RESPONSE;
       }

	if (unlikely(err & TFILE_ERR)) {
		// task file error, dump the SATA information
		oczpcie_diag_sata_error(oczi, task, (struct oczpcie_dev_to_host_fis *)resp->ending_fis);
	}

	return stat;
}

void oczpcie_set_sense(u8 *buffer, int len, int d_sense,
		int key, int asc, int ascq)
{
	memset(buffer, 0, len);

	if (d_sense) {
		/* Descriptor format */
		if (len < 4) {
			oczpcie_printk("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x72;		/* Response Code	*/
		if (len > 1)
			buffer[1] = key;	/* Sense Key */
		if (len > 2)
			buffer[2] = asc;	/* ASC	*/
		if (len > 3)
			buffer[3] = ascq;	/* ASCQ	*/
	} else {
		if (len < 14) {
			oczpcie_printk("Length %d of sense buffer too small to "
				"fit sense %x:%x:%x", len, key, asc, ascq);
		}

		buffer[0] = 0x70;		/* Response Code	*/
		if (len > 2)
			buffer[2] = key;	/* Sense Key */
		if (len > 7)
			buffer[7] = 0x0a;	/* Additional Sense Length */
		if (len > 12)
			buffer[12] = asc;	/* ASC */
		if (len > 13)
			buffer[13] = ascq; /* ASCQ */
	}

	return;
}

static int oczpcie_slot_err(struct oczpcie_info *oczi, struct oczpcie_task *task,
			 u32 slot_idx, int show_err)
{
	extern int error_control;
	struct oczpcie_slot_info *slot = &oczi->slot_info[slot_idx];
	int stat;
	u32 err_dw0 = le32_to_cpu(*(u32 *)slot->response);
	u32 err_dw1 = le32_to_cpu(*((u32 *)slot->response + 1));

	if (unlikely(error_control)) {
		if (error_control > ERR_CTRL_STOP_PHY) {
			if (error_control > ERR_CTRL_STOP_CONTROLLER) {
				extern int driver_halted_on_error;

				driver_halted_on_error = 1;
			}
			oczi->prv_info->errored_phys = ~0;
		}
		else {
			oczi->prv_info->errored_phys |= ( 1 << calc_device(oczi, task->device_number));
		}
	}

	if (show_err)
		oczpcie_diag_decode_err0(oczi, task, slot_idx, err_dw0, err_dw1);

	if (err_dw0 & CMD_ISS_STPD)
		chip_issue_stop(oczi);

	chip_command_active(oczi, slot_idx);

	stat = OCZPCIE_PROTO_RESPONSE;
	oczpcie_sata_done(oczi, task, slot_idx, err_dw0);

	return stat;
}

// caller must hold oczi->lock
static inline void run_queue(struct oczpcie_task *task)
{
	if (!list_empty(&task->oczi->task_queue[task->device_number])) {
		struct oczpcie_task *queue_task;

		queue_task = list_first_entry(&task->oczi->task_queue[task->device_number], struct oczpcie_task, list);
		// if we manage to send it to the card, remove it from the queue
		if (oczpcie_queue_command(queue_task, queue_task->oczi) == 0) {
			list_del(&queue_task->list);
		}
	}
}

int oczpcie_slot_complete(struct oczpcie_info *oczi, u32 rx_desc)
{
	u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
	struct oczpcie_slot_info *slot = &oczi->slot_info[slot_idx];
	struct oczpcie_task *task = slot->task;
	struct task_status_struct *tstat;
	enum exec_status sts;
	void (*done)(struct oczpcie_task *);

	if (unlikely(!task || !task->slot))
		return -1;

	oczi->timeout[task->device_number] = 0;
	oczi->devices[task->device_number].timeout[task->slot->slot_tag] = 0;

	tstat = &task->task_status;

	memset(tstat, 0, sizeof(*tstat));
	tstat->resp = TASK_COMPLETE;

	/* error info record present */
	if (unlikely((rx_desc & RXQ_ERR) && (*(u32 *) slot->response))) {
		u8 reg_set = oczi->devices[task->device_number].taskfileset;

		tstat->stat = oczpcie_slot_err(oczi, task, slot_idx, !(rx_desc & RXQ_SLOT_RESET));
		tstat->resp = TASK_RETRY_NEEDED;
		oczpcie_slot_task_free(oczi, task, slot, slot_idx);
		if (le32_to_cpu((*(u32 *)slot->response)) == ACK_NAK_TO) {
			printk("Command timeout detected\n");
		}
		// the RXQ_SLOT_RESET bit will be set if we are already processing this as an error, don't look for new errors
		if (task->ata_task.use_ncq && !(rx_desc & RXQ_SLOT_RESET)) {
			int tag, was_okay;

			was_okay = (oczi->devices[task->device_number].dev_status == OCZPCIE_DEV_NORMAL);
			oczi->devices[task->device_number].dev_status = OCZPCIE_DEV_EH;
			for (tag = 0; tag < MAX_NCQ_DEPTH; tag++) {
				int slot_idx = calc_slot(task->device_number, tag);
				if (oczi->slot_info[slot_idx].task) {
					*(u32 *)oczi->slot_info[slot_idx].response = cpu_to_le32(TFILE_ERR);
					oczpcie_slot_complete(oczi, slot_idx | RXQ_ERR | RXQ_SLOT_RESET);
					chip_command_active(oczi, slot_idx);
					oczpcie_int_rx(oczi, 0);
				}
			}
			chip_free_reg_set(oczi, &reg_set);
			chip_assign_specified_reg_set(oczi, oczi->devices[task->device_number].taskfileset);
			if (was_okay) {
				oczpcie_diag_handle_ncq_error(oczi, &oczi->devices[task->device_number]);
			}
		}

		goto out;
	}

	tstat->stat = oczpcie_sata_done(oczi, task, slot_idx, 0);
	oczpcie_slot_task_free(oczi, task, slot, slot_idx);

out:
	sts = tstat->stat;

	run_queue(task);
	done = task->task_done;
	task->task_done = NULL;
	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_unlock_bh(&oczi->lock);
	else
		spin_unlock(&oczi->lock);

	if (done)
		done(task);

	if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_lock_bh(&oczi->lock);
	else
		spin_lock(&oczi->lock);

	return sts;
}

static void oczpcie_work_queue(struct work_struct *work)
{
	struct delayed_work *dw = container_of(work, struct delayed_work, work);
	struct oczpcie_wq *mwq = container_of(dw, struct oczpcie_wq, work_q);
	struct oczpcie_info *oczi = mwq->oczi;
	unsigned long flags;

	spin_lock_irqsave(&oczi->lock, flags);
	if (mwq->handler & PHY_PLUG_EVENT) {
		dev_printk(KERN_ERR, oczi->dev, "PHY unplugged event\n");
	}
	list_del(&mwq->entry);
	spin_unlock_irqrestore(&oczi->lock, flags);
	kfree(mwq);
}

static int oczpcie_handle_event(struct oczpcie_info *oczi, void *data, int handler)
{
	struct oczpcie_wq *mwq;
	int ret = 0;

	mwq = kmalloc(sizeof(struct oczpcie_wq), GFP_ATOMIC);
	if (mwq) {
		mwq->oczi = oczi;
		mwq->data = data;
		mwq->handler = handler;
		OCZPCIE_INIT_DELAYED_WORK(&mwq->work_q, oczpcie_work_queue, mwq);
		list_add_tail(&mwq->entry, &oczi->wq_list);
		schedule_delayed_work(&mwq->work_q, HZ * 2);
	} else
		ret = -ENOMEM;

	return ret;
}

static void oczpcie_sig_time_out(unsigned long tphy)
{
	struct oczpcie_phy *phy = (struct oczpcie_phy *)tphy;
	struct oczpcie_info *oczi = phy->oczi;
	u8 phy_no;

	for (phy_no = 0; phy_no < N_PHY; phy_no++) {
		if (&oczi->phy[phy_no] == phy) {
			oczpcie_dprintk("Get signature time out, reset phy %d\n",
				phy_no+oczi->id*N_PHY);
			chip_phy_reset(oczi, phy_no, OCZPCIE_HARD_RESET);
		}
	}
}

void oczpcie_int_port(struct oczpcie_info *oczi, int phy_no, u32 events)
{
	u32 tmp;
	struct oczpcie_phy *phy = &oczi->phy[phy_no];

	phy->irq_status = oczpcie_read_port_irq_stat(oczi, phy_no);
	oczpcie_write_port_irq_stat(oczi, phy_no, phy->irq_status);
	oczpcie_dprintk("phy %d ctrl sts=0x%08X.\n", phy_no+oczi->id*N_PHY,
		oczpcie_read_phy_ctl(oczi, phy_no));
	oczpcie_dprintk("phy %d irq sts = 0x%08X\n", phy_no+oczi->id*N_PHY,
		phy->irq_status);

	/*
	* events is port event now ,
	* we need check the interrupt status which belongs to per port.
	*/

	if (phy->irq_status & PHYEV_DCDR_ERR) {
		oczpcie_dprintk("phy %d STP decoding error.\n",
		phy_no + oczi->id*N_PHY);
	}

	if (phy->irq_status & PHYEV_POOF) {
		mdelay(500);
		if (!(phy->phy_event & PHY_PLUG_OUT)) {
			int dev_sata = phy->phy_type & PORT_TYPE_SATA;
			int ready;
			// FIXME: Release tasks
			phy->phy_event |= PHY_PLUG_OUT;
			chip_clear_srs_irq(oczi, 0, 1);
			oczpcie_handle_event(oczi,
				(void *)(unsigned long)phy_no,
				PHY_PLUG_EVENT);
			ready = oczpcie_is_phy_ready(oczi, phy_no);
			if (ready || dev_sata) {
					chip_phy_reset(oczi,
							phy_no, OCZPCIE_SOFT_RESET);
				return;
			}
		}
	}

	if (phy->irq_status & PHYEV_COMWAKE) {
		tmp = oczpcie_read_port_irq_mask(oczi, phy_no);
		oczpcie_write_port_irq_mask(oczi, phy_no,
					tmp | PHYEV_SIG_FIS);
		if (phy->timer.function == NULL) {
			phy->timer.data = (unsigned long)phy;
			phy->timer.function = oczpcie_sig_time_out;
			phy->timer.expires = jiffies + 5*HZ;
			add_timer(&phy->timer);
		}
	}
	if (phy->irq_status & (PHYEV_SIG_FIS | PHYEV_ID_DONE)) {
		phy->phy_status = oczpcie_is_phy_ready(oczi, phy_no);
		oczpcie_dprintk("notify plug in on phy[%d]\n", phy_no);
		if (phy->phy_status) {
			mdelay(10);
			chip_detect_porttype(oczi, phy_no);
			if (phy->phy_type & PORT_TYPE_SATA) {
				tmp = oczpcie_read_port_irq_mask(
						oczi, phy_no);
				tmp &= ~PHYEV_SIG_FIS;
				oczpcie_write_port_irq_mask(oczi,
							phy_no, tmp);
			}
			oczpcie_update_phyinfo(oczi, phy_no, 0);
			if (phy->phy_type & PORT_TYPE_SAS) {
				BUG_ON(1);
			}

			/* whether driver is going to handle hot plug */
			if (phy->phy_event & PHY_PLUG_OUT) {
				oczpcie_dprintk(KERN_ERR "Received unhandler hot plug event\n");
				phy->phy_event &= ~PHY_PLUG_OUT;
			}
		} else {
			oczpcie_dprintk("plugin interrupt but phy%d is gone\n",
				phy_no + oczi->id*N_PHY);
		}
	} else if (phy->irq_status & PHYEV_BROAD_CH) {
		oczpcie_dprintk("phy %d broadcast change.\n",
			phy_no + oczi->id*N_PHY);
		oczpcie_handle_event(oczi, (void *)(unsigned long)phy_no,
				EXP_BRCT_CHG);
	}
}

int oczpcie_int_rx(struct oczpcie_info *oczi, bool self_clear)
{
	u32 rx_prod_idx, rx_desc;
	bool attn = false;

	/* the first dword in the RX ring is special: it contains
	 * a mirror of the hardware's RX producer index, so that
	 * we don't have to stall the CPU reading that register.
	 * The actual RX ring is offset by one dword, due to this.
	 */
	rx_prod_idx = oczi->rx_cons;
	oczi->rx_cons = le32_to_cpu(oczi->rx[0]);
	if (oczi->rx_cons == 0xfff)	/* h/w hasn't touched RX ring yet */
		return 0;

	/* The CMPL_Q may come late, read from register and try again
	* note: if coalescing is enabled,
	* it will need to read from register every time for sure
	*/
	if (unlikely(oczi->rx_cons == rx_prod_idx))
		oczi->rx_cons = oczpcie_rx_update(oczi) & RX_RING_SZ_MASK;

	if (oczi->rx_cons == rx_prod_idx)
		return 0;

	while (oczi->rx_cons != rx_prod_idx) {
		/* increment our internal RX consumer pointer */
		rx_prod_idx = (rx_prod_idx + 1) & (OCZPCIE_RX_RING_SZ - 1);
		rx_desc = le32_to_cpu(oczi->rx[rx_prod_idx + 1]);
		if (unlikely(rx_desc == ~0)) {
			udelay(1000);
			rx_desc = le32_to_cpu(oczi->rx[rx_prod_idx + 1]);
			if (rx_desc == ~0) {
				dev_printk(KERN_WARNING, oczi->dev, "Skip slot\n");
				continue;
			}
			dev_printk(KERN_WARNING, oczi->dev, "Recover slot %x\n", rx_desc);
		}
		oczi->rx[rx_prod_idx + 1] = ~0;

		if (likely(rx_desc & RXQ_DONE))
			oczpcie_slot_complete(oczi, rx_desc);
		if (rx_desc & RXQ_ATTN) {
			attn = true;
		} else if (rx_desc & RXQ_ERR) {
			if (!(rx_desc & RXQ_DONE))
				oczpcie_slot_complete(oczi, rx_desc);
		} else if (rx_desc & RXQ_SLOT_RESET) {
			u32 slot_idx = rx_desc & RXQ_SLOT_MASK;
			struct oczpcie_slot_info *slot = &oczi->slot_info[slot_idx];
			struct oczpcie_task *task = slot->task;

			oczpcie_slot_free(&oczi->devices[task->device_number], rx_desc);
		}
	}

	if (attn && self_clear)
		oczpcie_int_full(oczi);
	return 0;
}
