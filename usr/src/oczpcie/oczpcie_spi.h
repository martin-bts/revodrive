/*
 * oczpcie_spi.h
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

#ifndef OCZPCIE_SPI_H_
#define OCZPCIE_SPI_H_

int oczpcie_spi_read_hha_info(struct oczpcie_prv_info *priv, struct hba_info_page *hba_info);
int oczpcie_spi_read_config_info(struct oczpcie_prv_info *priv, struct oczpcie_config_data *config_data);
int oczpcie_spi_flash_bios(struct oczpcie_prv_info *priv, char *buffer, int len);
int oczpcie_spi_read_address(struct oczpcie_prv_info *priv, int address, void *buffer, int len);
int oczpcie_spi_update_bios(struct oczpcie_prv_info *priv, char *buffer, int len);

#endif /* OCZPCIE_SPI_H_ */
