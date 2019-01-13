/*
 * sg_io.c
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

#include	<linux/types.h>
#include	<linux/blkdev.h>
#include	<linux/ioctl.h>
#include	<linux/ata.h>
#include	<scsi/scsi.h>
#include	"sg_io.h"
#include	"oczpcie_iface.h"
#include	"util.h"
#include	"oczpcie_spi.h"

static int ocz_specific_get_bios_info(struct oczpcie_prv_info *priv, struct block_device *bdev, sg_io_hdr_t *io_hdr)
{
	int ret = 0;
	char *info;
	struct oczpci_config_data *config;

	info = kmalloc(io_hdr->dxfer_len, GFP_KERNEL);
	if (unlikely(!info)) {
		return -ENOMEM;
	}

	ret = oczpcie_spi_read_address(priv, OCZ_SPI_CONFIG_ADDR, info, io_hdr->dxfer_len);
	if ( ret < 0) {
		oczpcie_dprintk ("Could not read BIOS config\n");
		ret = -EINVAL;
		goto free;
	}

	config = (struct oczpci_config_data *) info;
	if (unlikely(copy_to_user((void __user *)io_hdr->dxferp, info, io_hdr->dxfer_len)))
		ret = -EFAULT;

free:
	kfree (info);

	return ret;
}

static int ocz_specific_update_bios(struct oczpcie_prv_info *priv, struct block_device *bdev, sg_io_hdr_t *io_hdr)
{
	int ret = 0;
	char *info;

	info = kmalloc(io_hdr->dxfer_len, GFP_KERNEL);
	if (unlikely(!info))
		return -ENOMEM;

	ret = copy_from_user(info, (void __user *) io_hdr->dxferp, io_hdr->dxfer_len);
	if (unlikely(ret != 0)) {
		ret = -EFAULT;
		goto free;
	}
	ret = oczpcie_spi_update_bios(priv, info, io_hdr->dxfer_len);
	if (ret < 0 )
		ret = -EINVAL;

free:
	kfree (info);
	return ret;
}

static int ocz_specific_cmd(struct oczpcie_prv_info *priv, u8 *cdb, struct block_device *bdev, sg_io_hdr_t *io_hdr)
{
	u8 ret, ocz_cmd;
	ocz_cmd = cdb[10];

	switch (ocz_cmd) {
		case OCZ_CDB_BIOS_UPDATE:
			ret = ocz_specific_update_bios(priv, bdev, io_hdr);
			break;

		case OCZ_CDB_BIOS_GETINFO:
			ret = ocz_specific_get_bios_info(priv, bdev, io_hdr);
			break;

		default:
			ret = -EINVAL;
			break;
	}
	return ret;
}

int oczpcie_sg_io(struct block_device *bdev, unsigned cmd, unsigned long arg)
{
	sg_io_hdr_t io_hdr;
	u8 cdb[16];
	u8 sense[SENSE_BUFFERSIZE];
	u8 ata_cmd;
	struct oczpcie_issue_command command_info;
	struct request_queue *q;
	struct oczpcie_prv_info *priv;
	struct oczpcie_info *oczi;
	int ret = 0;

	memset(&command_info, 0, sizeof(command_info));

	if (unlikely(copy_from_user(&io_hdr, (void __user *)arg, sizeof(io_hdr))))
		return -EFAULT;

	if (unlikely(io_hdr.cmd_len > 16))
		return -EINVAL;

	if (unlikely(copy_from_user(cdb, io_hdr.cmdp, io_hdr.cmd_len)))
		return -EFAULT;

	// only ATA pass-through is allowed
	if (unlikely(cdb[0] != 0x85))
		return -EINVAL;

	if (unlikely(io_hdr.dxfer_len & 0x1FF))	// must be a multiple of sector size
		return -EINVAL;

	if (io_hdr.iovec_count != 0)	// FIXME: Need to support SG list
		return -EINVAL;

	command_info.dev_id = oczpcie_get_dev_id_from_block_device(bdev->bd_dev,bdev_get_queue(bdev), &oczi); // temporary id to check it

	if (unlikely(command_info.dev_id == -1))
		return -ENODEV;

	command_info.dev_id = (MINOR(bdev->bd_dev) >> PARTITION_SHIFT);	// real id

	q = bdev_get_queue(bdev);
	priv = (struct oczpcie_prv_info *)q->queuedata;
	if (unlikely(priv == NULL))
		return -ENODEV;


	ata_cmd = cdb[14];

	switch (ata_cmd) {
		case ATA_CMD_SEC_SET_PASS:
		case ATA_CMD_SEC_UNLOCK:
		case ATA_CMD_SEC_ERASE_UNIT:
			command_info.is_write = 1;
			command_info.timeout = 120 * HZ;
			// drop through
		case ATA_CMD_ID_ATA:
			command_info.use_dma = 1;
			break;

		case ATA_CMD_SEC_ERASE_PREP:
			break;

		case ATA_CMD_SMART:
			if (CDB_IS_OCZ_SPEC_PASS (cdb)) {
				return ocz_specific_cmd(priv, cdb, bdev, &io_hdr);
			}
			command_info.is_write = (io_hdr.dxfer_direction == SG_DXFER_TO_DEV);
			command_info.use_dma = (io_hdr.dxfer_len > 0);
			command_info.features = cdb[4];
			command_info.features |= (cdb[3] << 8);
			break;
		case ATA_CMD_DOWNLOAD_MICRO:
			command_info.is_write = (io_hdr.dxfer_direction == SG_DXFER_TO_DEV);
			command_info.use_dma = (io_hdr.dxfer_len > 0);
			command_info.features = cdb[4];
			command_info.features |= (cdb[3] << 8);
			//due to a workaround for some controller chips in the tools we set the extend bit for download microcode
			//however it's a 28bit only command so this mangles the command sent to the disks
			cdb[1] &= ~0x1; //clear extend bit
			break;

		default:
			return -EINVAL;
	}

	command_info.cmd = ata_cmd;

	command_info.lba = cdb[8];
	if (cdb[1] & 1) { // extended addresses
		command_info.lba |= ((u64)cdb[7] << 8);
		command_info.lba |= ((u64)cdb[10] << 16);
		command_info.lba |= ((u64)cdb[9] << 24);
		command_info.lba |= ((u64)cdb[12] << 32);
		command_info.lba |= ((u64)cdb[11] << 40);
	}
	else {
		command_info.lba |= ((u64)cdb[10] << 8);
		command_info.lba |= ((u64)cdb[12] << 16);
	}

	command_info.num_pages = alloc_seperate_pages(io_hdr.dxfer_len, &command_info.data, GFP_KERNEL);
	if (unlikely(command_info.num_pages < 0))
		return -ENOMEM;

	command_info.len = io_hdr.dxfer_len;

	if (unlikely(copy_from_user_to_pages(command_info.data, io_hdr.dxferp, io_hdr.dxfer_len))) {
		ret = -EFAULT;
		goto free_pages;
	}

	sema_init(&command_info.sem, 0);

	ret = oczpcie_issue_command(priv, GFP_NOIO, &command_info);
	if (unlikely(ret))
		goto free_pages;
	if (unlikely(down_interruptible(&command_info.sem))) {
		oczpcie_abort_issue_command(priv, &command_info);
		ret = -EINTR;
		goto free_pages;
	}

	if (unlikely(command_info.stat)) {
		ret = -EIO;
		goto free_pages;
	}

	if (unlikely(copy_to_user_from_pages(io_hdr.dxferp, command_info.data ,io_hdr.dxfer_len))) {
		ret = -EFAULT;
		goto free_pages;
	}

	memset(sense, 0, SENSE_BUFFERSIZE);
	if (cdb[0] == 0x85) { // ATA pass-through is different, generates a CHECK_CONDITION with the ATA registers
#if 0
		// code for old toolbox, does not cope with descriptor format
		io_hdr.status = 0;
		io_hdr.masked_status = 0;
		io_hdr.driver_status = 0;
		io_hdr.host_status = DID_OK;
		io_hdr.sb_len_wr = 0;
#endif
		// code for newer toolbox
		// FIXME: Need to arrange for the command_info paramater to be updated from the device-to-host FIS on error
		io_hdr.status = SAM_STAT_CHECK_CONDITION;
		io_hdr.masked_status = (SAM_STAT_CHECK_CONDITION >> 1);
		io_hdr.driver_status = DRIVER_SENSE;
		io_hdr.host_status = DID_OK;
		sense[0] = 0x72; // current and descriptor format
		sense[8] = 0x09;
		sense[7] = 0x0e; // additional bytes
		sense[9] = 0x0c;

		sense[10] = 0;
		sense[11] = 0;	// error register
		sense[13] = command_info.len;
		sense[15] = command_info.lba & 0xff;
		sense[17] = (command_info.lba >> 8) & 0xff;
		sense[19] = (command_info.lba >> 16) & 0xff;
		sense[21] = 0; // status register

		if (cdb[1] & 1) { // extended addresses
			sense[10] = 1;
			sense[12] = command_info.len;
			sense[14] = (command_info.lba >> 24) & 0xff;
			sense[16] = (command_info.lba >> 32) & 0xff;
			sense[18] = (command_info.lba >> 40) & 0xff;
		}
		io_hdr.sb_len_wr = (io_hdr.mx_sb_len < SENSE_BUFFERSIZE) ? io_hdr.mx_sb_len : SENSE_BUFFERSIZE;
	} else {
		// assume okay
		io_hdr.status = SAM_STAT_GOOD;
		io_hdr.masked_status = GOOD;
		io_hdr.host_status = DID_OK;
		io_hdr.driver_status = DRIVER_OK;
		io_hdr.sb_len_wr = 0;
	}

	if (io_hdr.sb_len_wr)
		if (unlikely(copy_to_user((void __user *)io_hdr.sbp, sense, io_hdr.sb_len_wr)))
			return -EFAULT;

	if (unlikely(copy_to_user((void __user *)arg, &io_hdr, sizeof(io_hdr))))
		return -EFAULT;

free_pages:
	if (command_info.num_pages > 0)
		free_seperate_pages(command_info.data, command_info.num_pages);

	return ret;
}

