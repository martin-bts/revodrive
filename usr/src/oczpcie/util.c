/*
 * util.c
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

#include	<linux/kernel.h>
#include	<linux/types.h>
#include	<linux/slab.h>
#include	<linux/mm.h>
#include	<linux/pci.h>
#include	<asm/uaccess.h>

void ata_get_string(char *result, void *source, int start, int end)
{
	__le16 *data = (__le16 *)source;
	int i;
	int j = 0;

	for (i = start; i <= end; i++) {
		result[j++] = le16_to_cpu(data[i]) >> 8;
		result[j++] = le16_to_cpu(data[i]) & 0xFF;
	}
	result[j--] = '\000';
	// remove trailing spaces
	while (j && result[j] == ' ')
		result[j--] = '\000';
}

u64 ata_get_qword(void *source, int offset)
{
	__le16 *data = (__le16 *)source;
	data += offset;
	return le64_to_cpu(*(__le64 *)data);
}

u16 ata_get_word(void *source, int offset)
{
	__le16 *data = (__le16 *)source;
	return le16_to_cpu(*(data+offset));
}

int check_firmware_version(struct device *dev, char *ata_model, char *ata_fw)
{
	long first, second;
	int len, err;
	int is_e = 0;
	char *point;

	if (strncmp(ata_model, "OCZ Z-DRIVE R4", 14) && strncmp(ata_model, "OCZ-REVODRIVE3", 14)) {
		// Not a Z-Drive or RevoDrive 3
		return 0;
	}

	len = strlen(ata_fw);
	point = strchr(ata_fw, '.');
	if (point == NULL) {
		// Don't recognise format
		return 0;
	}

	*point = '\000';

	// check firmware type by looking for 'E' at end
	if (ata_fw[len-1] == 'E') {
		is_e = 1;
		ata_fw[len-1] = '\000';
	}

	err = strict_strtol(ata_fw, 10, &first);
	err = strict_strtol(point+1, 10, &second);

	if (is_e) {
		// must be at least 3.20
		if (first < 3)
			return -1;

		if (first == 3 && second < 20)
			return -1;
	}
	else {
		// must be at least 2.25
		if (first < 2)
			return -1;

		if (first == 2 && second < 25)
			return -1;
	}

	return 0;
}

/*
 * Allocate enough pages for len bytes.
 * Note we allocate each page separately rather than contiguously, this
 * is because we don't need contiguous pages and there is a much greater
 * chance of the allocation succeeding for order 0.
 * Caller must free pages with free_seperate_pages(), if number of pages
 * returned >= 0
 */
int alloc_seperate_pages(int len, struct page ***pages_pointer, int flags)
{
	int num_pages, i, j;
	struct page **pages;

	num_pages = ((len + PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (unlikely(!num_pages))
		return 0;

	*pages_pointer = kmalloc(sizeof(struct page *) * num_pages, flags);
	if (unlikely(!(*pages_pointer)))
		return -ENOMEM;

	pages = *pages_pointer;

	for (i = 0; i < num_pages; i++) {
		pages[i] = alloc_page(flags);
		if (unlikely(!pages[i])) {
			// free what we have already allocated
			for (j = 0; j < i - 1; j++) {
				__free_page(pages[i]);
			}
			return -ENOMEM;
		}
	}

	return num_pages;
}

void free_seperate_pages(struct page **pages, int num_pages)
{
	int i;

	if (unlikely(!num_pages))
		return;

	for (i = 0; i < num_pages; i++) {
		__free_page(pages[i]);
	}
	kfree(pages);
}

int copy_from_user_to_pages(struct page **pages, u8 *from, int len)
{
	int page = 0;
	int total = 0;
	while (len > 0)
	{
		int xfer_len = len > PAGE_SIZE ? PAGE_SIZE : len;
		if (unlikely(copy_from_user(page_address(pages[page]), from + total, xfer_len)))
			return -EFAULT;
		total += xfer_len;
		len -= xfer_len;
		page++;
	}

	return 0;
}

int copy_to_user_from_pages(u8 *to, struct page **pages, int len)
{
	int page = 0;
	int total = 0;
	while (len > 0)
	{
		int xfer_len = len > PAGE_SIZE ? PAGE_SIZE : len;
		if (unlikely(copy_to_user(to + total, page_address(pages[page]), xfer_len)))
			return -EFAULT;
		total += xfer_len;
		len -= xfer_len;
		page++;
	}

	return 0;
}
