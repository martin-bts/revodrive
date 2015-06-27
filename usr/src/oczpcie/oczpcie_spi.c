/*
 * oczpcie_spi.c
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


#include	<linux/kernel.h>
#include	"oczpcie_main.h"
#include	"chip.h"

#define	SPI_FLASH_SIZE	0x40000
#define	MAX_BIOS_SIZE	0x17000
#define	SPI_PARAM_ADDRESS	SPI_FLASH_SIZE - 0x100
#define	SPI_CONFIG_ADDRESS	0x20000

#define	SPI_READ	0x3
#define	SPI_READ_STATUS	0x5
#define	SPI_WRITE_ENABLE	0x6
#define	SPI_WRITE	0x2


#define	SPI_AML_IDENTIFY	0x15
#define	SPI_AML_4_IDENTIFY	0x9F
#define	SPI_WIN_IDENTIFY	0xAB

enum {
	SPI_FLASH_TYPE_UNKNOWN,
	SPI_FLASH_TYPE_AML,
	SPI_FLASH_TYPE_AML_4,
	SPI_FLASH_TYPE_WIN,
	SPI_FLASH_TYPE_SENTINEL	// must be last
};

// these arrays are indexed by the above index, zero means the command is not available
static u8 spi_unprotect_sector_cmd[SPI_FLASH_TYPE_SENTINEL] = {
		0,	0, 0x39, 0
};
static u8 spi_erase_sector_cmd[SPI_FLASH_TYPE_SENTINEL] = {
		0,	0x52, 0xD8, 0xD8
};
static u8 spi_chip_erase_cmd[SPI_FLASH_TYPE_SENTINEL] = {
		0,	0x62, 0x60, 0xC7
};

/* These are the SPI routines needed for access to the BIOS */

static u32 spi_read_data(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs_ex - 0x10200;
	return mr32(SPI_RD_DATA_REG);
}

static void spi_write_data(struct oczpcie_info *oczi, u32 data)
{
	void __iomem *regs = oczi->regs_ex - 0x10200;
	 mw32(SPI_WR_DATA_REG, data);
}

static int spi_buildcmd(struct oczpcie_info *oczi, u32 *dwCmd, u8 cmd,
				u8 read, u8 length, u32 addr)
{
	void __iomem *regs = oczi->regs_ex - 0x10200;
	u32  dwTmp;

	dwTmp = ((u32)cmd << 8) | ((u32)length << 4);
	if (read)
		dwTmp |= SPI_CTRL_READ;

	if (addr != OCZPCIE_MAX_U32) {
		mw32(SPI_ADDR_REG, (addr & 0x0003FFFFL));
		dwTmp |= SPI_ADDR_VLD;
	}

	*dwCmd = dwTmp;
	return 0;
}

static void spi_issuecmd(struct oczpcie_info *oczi, u32 cmd)
{
	void __iomem *regs = oczi->regs_ex - 0x10200;
	mw32(SPI_CTRL_REG, cmd | SPI_CTRL_SpiStart);
}

static int spi_waitdataready(struct oczpcie_info *oczi, u32 timeout)
{
	void __iomem *regs = oczi->regs_ex - 0x10200;
	u32   i, dwTmp;

	for (i = 0; i < timeout; i++) {
		dwTmp = mr32(SPI_CTRL_REG);
		if (!(dwTmp & SPI_CTRL_SpiStart))
			return 0;
		udelay(10);
	}
	return -1;
}

static int spi_poll_status(struct oczpcie_info *oczi, u8 mask, u8 bit, u32 timeout)
{
	int i;

	for (i = 0; i < timeout; i++) {
		u32 dwTmp;

		spi_buildcmd(oczi, &dwTmp, SPI_READ_STATUS, 1, 1, 0);
		spi_issuecmd(oczi, dwTmp);
		if (unlikely(spi_waitdataready(oczi, 10000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout while polling status\n");
			return -1;
		}
		dwTmp = spi_read_data(oczi);
		if ((dwTmp & mask) == bit)
			return 0;

		udelay(20);
	}
	dev_printk(KERN_ERR, oczi->dev, "SPI status timeout\n");
	return -1;
}

static void spi_write_enable(struct oczpcie_info *oczi)
{
	u32 dwTmp;

	spi_buildcmd(oczi, &dwTmp, SPI_WRITE_ENABLE, 0, 0, -1);
	spi_issuecmd(oczi, dwTmp);
	if (unlikely(spi_waitdataready(oczi, 10000))) {
		dev_printk(KERN_ERR, oczi->dev, "SPI Timeout when setting write enable\n");
		return;
	}
	if (unlikely(spi_poll_status(oczi, 3, 2, 30000)))
		dev_printk(KERN_ERR, oczi->dev, "SPI Timeout when polling status for write enable\n");
}

static int spi_read(struct oczpcie_info *oczi, u8 *buffer, int address, int count)
{
	int pos;

	if (unlikely(address & 3)) {
		oczpcie_printk("SPI read address not aligned\n");
		return -1;
	}

	pos = 0;
	while (count) {
		int size = count > 4 ? 4 : count;
		u32 dwCmd;
		u32 res;
		int i;

		spi_buildcmd(oczi, &dwCmd, SPI_READ, 1, size, address);
		spi_issuecmd(oczi, dwCmd);
		if (unlikely(spi_waitdataready(oczi, 10000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during read request\n");
			return -1;
		}
		res = spi_read_data(oczi);
		for (i = 0; i < size; i++) {
			buffer[pos++] = ((u8 *)&res)[i];
		}
		count -= size;
		address += size;
	}
	return 0;
}

static int spi_write(struct oczpcie_info *oczi, u8 *buffer, int address, int count)
{
	int pos;

	if (unlikely(address & 3)) {
		oczpcie_printk("SPI write address not aligned\n");
		return -1;
	}

	pos = 0;
	while (count) {
		int size = count > 4 ? 4 : count;
		u32 dwCmd;
		u32 res;
		int i;

		spi_write_enable(oczi);
		for (i = 0; i < size; i++) {
			((u8 *)&res)[i] = buffer[pos++];
		}
		spi_write_data(oczi, res);
		spi_buildcmd(oczi, &dwCmd, SPI_WRITE, 0, size, address);
		spi_issuecmd(oczi, dwCmd);
		if (unlikely(spi_waitdataready(oczi, 10000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during write request\n");
			return -1;
		}
		if (unlikely(spi_poll_status(oczi, 1, 0, 5000))) {
			return -1;
		}
		count -= size;
		address += size;
	}
	return 0;
}

static int spi_erase(struct oczpcie_info *oczi)
{
	u32 dwCmd;
	u8 cmd;
	// The whole flash is erased, only makes sense to call this
	// if you are just about to write a new one

	cmd = spi_chip_erase_cmd[oczi->flash_type];
	if (cmd == 0)
		return 0;
	spi_write_enable(oczi);
	spi_buildcmd(oczi, &dwCmd, cmd, 0, 0, 0);
	spi_issuecmd(oczi, dwCmd);
	if (unlikely(spi_waitdataready(oczi, 10000))) {
		dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during erase request\n");
		return -1;
	}
	if (unlikely(spi_poll_status(oczi, 3, 0, 300000))) {
		dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during erase\n");
		return -1;
	}
	return 0;
}

static int spi_erase_sector(struct oczpcie_info *oczi, int addr)
{
	u32 dwTmp;
	u8 cmd;

	cmd = spi_unprotect_sector_cmd[oczi->flash_type];
	if (cmd) {
		spi_buildcmd(oczi, &dwTmp, cmd, 0, 0, addr);
		spi_issuecmd(oczi, dwTmp);
		if (unlikely(spi_waitdataready(oczi, 10000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during un-protect sector request\n");
			return -1;
		}
		if (unlikely(spi_poll_status(oczi, 3, 0, 300000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during un-protect sector\n");
			return -1;
		}
	}

	cmd = spi_erase_sector_cmd[oczi->flash_type];
	if (cmd) {
		spi_write_enable(oczi);
		spi_buildcmd(oczi, &dwTmp, cmd, 0, 0, addr);
		spi_issuecmd(oczi, dwTmp);
		if (unlikely(spi_waitdataready(oczi, 10000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during sector erase request\n");
			return -1;
		}
		if (unlikely(spi_poll_status(oczi, 3, 0, 300000))) {
			dev_printk(KERN_ERR, oczi->dev, "SPI Timeout during sector erase\n");
			return -1;
		}
	}
	return 0;
}

static int spi_check_signature(struct hba_info_page *hba_info)
{
	if (hba_info->signature[0] == 77 &&
		hba_info->signature[1] == 82 &&
		hba_info->signature[2] == 86 &&
		hba_info->signature[3] == 76)
			return 0;

	return -1;
}

static int spi_verify_checksum(struct hba_info_page *hba_info)
{
	int i;
	u8 *data = (u8 *)hba_info;
	u8 sum = 0;

	for (i = 0; i < sizeof(struct hba_info_page); i++) {
		sum += data[i];
	}

	return sum != 0;
}

static void spi_identify_flash_type(struct oczpcie_info *oczi)
{
	u32 dwTmp;
	u32 type;

	if (oczi->flash_type)
		return;	// already identified

	spi_buildcmd(oczi, &dwTmp, SPI_AML_IDENTIFY, 1, 2, 0);
	spi_issuecmd(oczi, dwTmp);
	if (spi_waitdataready(oczi, 10000) == 0) {
		type = spi_read_data(oczi);
		if (type == 0x631f) {
			oczpcie_dprintk("Identified flash type as AML\n");
			oczi->flash_type = SPI_FLASH_TYPE_AML;
			return;
		}
	}

	spi_buildcmd(oczi, &dwTmp, SPI_AML_4_IDENTIFY, 1, 2, 0);
	spi_issuecmd(oczi, dwTmp);
	if (spi_waitdataready(oczi, 10000) == 0) {
		type = spi_read_data(oczi);
		switch (type) {
			case 0x441f:
			case 0x431f:
			case 0x9d7f:
				oczpcie_dprintk("Identified flash type as AML_4\n");
				oczi->flash_type = SPI_FLASH_TYPE_AML_4;
				return;
		}
	}
	spi_buildcmd(oczi, &dwTmp, SPI_WIN_IDENTIFY, 1, 2, 0);
	spi_issuecmd(oczi, dwTmp);
	if (spi_waitdataready(oczi, 10000) == 0) {
		type = spi_read_data(oczi);
		if (type == 0x1212) {
			oczpcie_dprintk("Identified flash type as Winbond\n");
			oczi->flash_type = SPI_FLASH_TYPE_WIN;
			return;
		}
	}

	oczi->flash_type = SPI_FLASH_TYPE_UNKNOWN;
	dev_printk(KERN_WARNING, oczi->dev, "Unknown SPI flash type, it will not be possible to update BIOS\n");
	return;
}

int oczpcie_spi_read_address(struct oczpcie_prv_info *priv, int address, void *buffer, int len)
{
	int ret;

	spin_lock(&priv->spi_lock);
	spi_identify_flash_type(priv->oczi[0]);
	ret = spi_read(priv->oczi[0], (u8 *)buffer, address, len);
	spin_unlock(&priv->spi_lock);
	return ret;
}

int oczpcie_spi_read_hha_info(struct oczpcie_prv_info *priv, struct hba_info_page *hba_info)
{
	if (oczpcie_spi_read_address(priv, SPI_PARAM_ADDRESS, (u8 *)hba_info, sizeof(struct hba_info_page)) == -1)
		goto error;

	if (spi_check_signature(hba_info)) {
		dev_printk(KERN_WARNING, priv->oczi[0]->dev, "BIOS has incorrect signature\n");
		goto error;
	}

	if (spi_verify_checksum(hba_info)) {
		dev_printk(KERN_WARNING, priv->oczi[0]->dev, "BIOS has incorrect checksum\n");
		goto error;
	}

	return 0;

error:
	// on error, mark the hba_info as invalid by setting all bytes to 0xFF
	memset(hba_info, 0xFF, sizeof(struct hba_info_page));
	return -1;
}

int oczpcie_spi_read_config_info(struct oczpcie_prv_info *priv, struct oczpcie_config_data *config_data)
{
	if (oczpcie_spi_read_address(priv, SPI_CONFIG_ADDRESS, (u8 *)config_data, sizeof(struct oczpcie_config_data)) == -1)
		return -1;

	return 0;
}

int oczpcie_spi_update_bios(struct oczpcie_prv_info *priv, char *buffer, int len)
{
	int i;

	if (unlikely(len > MAX_BIOS_SIZE)) {
		return -1;
	}

	spin_lock(&priv->spi_lock);

	spi_identify_flash_type(priv->oczi[0]);
	// erase the sectors we are going to write
	for (i = 0; i < len; i += 0x10000) {
		if (unlikely(spi_erase_sector(priv->oczi[0], i)))
			goto error;
	}

	if (unlikely(spi_write(priv->oczi[0], buffer, 0, len))) {
		dev_printk(KERN_ERR, priv->oczi[0]->dev, "BIOS write failed\n");
		goto error;
	}
	spin_unlock(&priv->spi_lock);
	return 0;

error:
	spin_unlock(&priv->spi_lock);
	return -1;
}

int oczpcie_spi_flash_bios(struct oczpcie_prv_info *priv, char *buffer, int len)
{
	// completely erase a re-program the flash
	return -1; // not yet tested, added for safety

	spin_lock(&priv->spi_lock);

	if (unlikely(len & 3)) {
		oczpcie_printk("BIOS length not aligned\n");
		goto error;
	}

	spi_identify_flash_type(priv->oczi[0]);
	if (unlikely(spi_erase(priv->oczi[0]))) {
		dev_printk(KERN_ERR, priv->oczi[0]->dev, "BIOS erase failed\n");
		goto error;
	}
	if (unlikely(spi_write(priv->oczi[0], buffer, 0, len))) {
		dev_printk(KERN_ERR, priv->oczi[0]->dev, "BIOS reprogram failed\n");
		goto error;
	}

	spin_unlock(&priv->spi_lock);
	return 0;

error:
	spin_unlock(&priv->spi_lock);
	return -1;
}
