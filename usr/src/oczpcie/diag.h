/*
 * diag.h
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

#ifndef DIAG_H_
#define DIAG_H_

void oczpcie_diag_decode_err0(struct oczpcie_info *oczi, struct oczpcie_task *task, u32 slot, u32 err0, u32 err1);
void oczpcie_diag_sata_error(struct oczpcie_info *oczi, struct oczpcie_task *task, struct oczpcie_dev_to_host_fis *fis);
void oczpcie_diag_handle_ncq_error(struct oczpcie_info *oczi, struct oczpcie_device *device);

#endif /* DIAG_H_ */
