/*
 * vca_iface.c
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

#include	<linux/version.h>
#include	<linux/fs.h>
#include	<linux/blkdev.h>
#include	"oczpcie_main.h"
#include	"oczpcie_iface.h"
#include	"oczpcie_spi.h"
#include	"vca_iface.h"

#define	MODE	(FMODE_READ | FMODE_WRITE | FMODE_EXCL | FMODE_EXEC)

static int blkdev_open_by_number(struct oczpcie_prv_info *priv, int device_id, struct block_device **device)
{
#if	LINUX_VERSION_CODE <  KERNEL_VERSION(2,6,38)
	*device = open_by_devnum(MKDEV(priv->block_major, device_id), MODE);
	if (unlikely(IS_ERR(*device))) {
#else
	*device = blkdev_get_by_dev(MKDEV(priv->block_major, device_id), MODE, priv);
	if (unlikely(IS_ERR_OR_NULL(*device))) {
#endif
		int ret = PTR_ERR(*device);
		*device = NULL;
		return ret;
	}
	return 0;
}

/* Ask to be notified as new cards are added
 * This will immediately notify of all cards that have already been added but not yet processed
 */

void oczpcie_vca_register_card_add_callback(register_card_callback_t card_callback)
{
	struct list_head *cursor;

	register_card_add_callback = card_callback;	// this will catch new cards, but run through the list for existing
	if (register_card_add_callback) {
		list_for_each(cursor, &card_list) {
			struct oczpcie_card_info *entry;
			struct oczpcie_prv_info *priv;
			struct pci_dev *pdev;

			entry = list_entry(cursor, struct oczpcie_card_info, list);
			priv = entry->priv;
			pdev = priv->oczi[0]->pdev;
			(*register_card_add_callback)(priv, priv->oczi[0]->n_phy + priv->oczi[1]->n_phy, pci_domain_nr(pdev->bus),
					pdev->bus->number, PCI_SLOT(pdev->devfn));

		}
	}
}
EXPORT_SYMBOL(oczpcie_vca_register_card_add_callback);

/* Ask to be notified when a card is removed
 *
 */
void oczpcie_vca_register_card_remove_callback(unregister_card_callback_t card_callback)
{
	register_card_remove_callback = card_callback;
}
EXPORT_SYMBOL(oczpcie_vca_register_card_remove_callback);

void oczpcie_vca_make_request(struct oczpcie_prv_info *priv, struct bio *bio)
{
	oczpcie_make_request(priv, GFP_NOIO, bio, DEFAULT_RETRIES);
}
EXPORT_SYMBOL(oczpcie_vca_make_request);


/* Open one of our devices
 * NB This allocates the block_device structure
 */
int oczpcie_vca_get_bdev(struct oczpcie_prv_info *priv, int device_id, struct block_device **device)
{
	return blkdev_open_by_number(priv, device_id, device);
}
EXPORT_SYMBOL(oczpcie_vca_get_bdev);

/* Close one of our devices
 * NB This frees the block_device structure
 */
void oczpcie_vca_put_bdev(struct oczpcie_prv_info *priv, struct block_device *bdev)
{
	blkdev_put(bdev, MODE);
}
EXPORT_SYMBOL(oczpcie_vca_put_bdev);

int oczpcie_vca_issue_command(struct oczpcie_prv_info *priv, struct oczpcie_issue_command *command_info)
{
	return oczpcie_issue_command(priv, GFP_NOIO, command_info);
}
EXPORT_SYMBOL(oczpcie_vca_issue_command);

void oczpcie_vca_abort_issue_command(struct oczpcie_prv_info *priv , struct oczpcie_issue_command *command_info)
{
	oczpcie_abort_issue_command(priv, command_info);
}
EXPORT_SYMBOL(oczpcie_vca_abort_issue_command);

int oczpcie_vca_read_bios(struct oczpcie_prv_info *priv, int address, void *buffer, int len)
{
	return oczpcie_spi_read_address(priv, address, buffer, len);
}
EXPORT_SYMBOL(oczpcie_vca_read_bios);
