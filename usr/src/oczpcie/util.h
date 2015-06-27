/*
 * util.h
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

#ifndef UTIL_H_
#define UTIL_H_

void ata_get_string(char *result, void *source, int start, int end);
u64 ata_get_qword(void *source, int offset);
u16 ata_get_word(void *source, int offset);
int check_firmware_version(struct device *dev, char *ata_model, char *ata_fw);
int alloc_seperate_pages(int len, struct page ***pages, int flags);
void free_seperate_pages(struct page **pages, int num_pages);
int copy_from_user_to_pages(struct page **pages, u8 *from, int len);
int copy_to_user_from_pages(u8 *to, struct page **pages, int len);


#endif /* UTIL_H_ */
