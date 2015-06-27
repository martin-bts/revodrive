/*
 * sg_io.h
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

#ifndef SG_IO_H_
#define SG_IO_H_

#include	<scsi/sg.h>

#define SCSI_CMD_SMART     0xB0
#define SCSI_CMD_WRITE_LOG 0xD6
#define SCSI_CMD_LBA_LOW   0xAA

#define OCZ_CDB_BIOS_REWRITE    	0x99	/*TBD, using (LBA mid field)*/
#define OCZ_CDB_BIOS_UPDATE         0x98    /*TBD, using (LBA mid field)*/
#define OCZ_CDB_BIOS_GETINFO        0xE1
#define OCZ_CDB_SF_SCT              0xC0

#define CDB_IS_OCZ_SPEC_PASS(cmd)   (   (cmd[4] == SCSI_CMD_WRITE_LOG) && \
										(cmd[8] == SCSI_CMD_LBA_LOW) \
									)

#define	SENSE_BUFFERSIZE	 96

#define OCZ_SPI_CONFIG_ADDR (0x20000L)

int oczpcie_sg_io(struct block_device *dev, unsigned cmd, unsigned long arg);

#endif /* SG_IO_H_ */
