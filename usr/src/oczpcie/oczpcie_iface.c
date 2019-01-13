/*
 * oczpcie_iface.c
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


#include	<linux/version.h>
#include	<linux/hdreg.h>
#include	<linux/slab.h>
#include	<linux/ata.h>
#include	"oczpcie_main.h"
#include	"chip.h"
#include	"ioctl.h"
#include	"util.h"
#include	"diag.h"
#include	"oczpcie_iface.h"
#include	"oczpcie_spi.h"
#include	"vca_iface.h"

// globals
// the board list
LIST_HEAD(card_list);
register_card_callback_t register_card_add_callback;
unregister_card_callback_t register_card_remove_callback;


#ifndef	DISABLE_THREADED_INTERRUPTS
static int disable_threaded_interrupts;
module_param(disable_threaded_interrupts, int, 0);
#endif	// DISABLE_THREADED_INTERRUPTS

#ifdef	ENABLE_VCA
static int disable_vca;
module_param(disable_vca, int, 0);
#else	// ENABLE_VCA
static int disable_vca = 1;
#endif	// ENABLE_VCA`
static int override_checks;
module_param(override_checks, int, 0);
int error_control;
module_param(error_control, int, 0);
int driver_halted_on_error;

// workaround for broken kernels/config
#if defined(CONFIG_XEN) && LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define	BROKEN_PHYS_MERGE
static inline int biovec_phys_mergeable(struct bio_vec *b1, struct bio_vec *b2)
{
	return __BIOVEC_PHYS_MERGEABLE(b1, b2);
}
#endif

static void oczpcie_phy_init(struct oczpcie_info *oczi, int phy_id)
{
	struct oczpcie_phy *phy = &oczi->phy[phy_id];

	phy->oczi = oczi;
#ifdef HAVE_KERNEL_TIMER_SETUP
	timer_setup(&phy->timer, NULL, 0);
#else
	init_timer(&phy->timer);
#endif
}

static void oczpcie_free(struct oczpcie_info *oczi)
{
	struct oczpcie_wq *mwq;
	int i;

	if (!oczi)
		return;

	for (i = 0; i < (1L << SLOT_WIDTH); i++) {
		struct oczpcie_slot_info *slot = &oczi->slot_info[i];
		if (slot->buf != NULL) {
			pci_pool_free(oczi->dma_pool, slot->buf, slot->buf_dma);
		}
	}
	if (oczi->dma_pool)
		pci_pool_destroy(oczi->dma_pool);

	if (oczi->tx)
		dma_free_coherent(oczi->dev,
				  sizeof(*oczi->tx) * OCZPCIE_CHIP_SLOT_SZ,
				  oczi->tx, oczi->tx_dma);
	if (oczi->rx_fis)
		dma_free_coherent(oczi->dev, OCZPCIE_RX_FISL_SZ,
				  oczi->rx_fis, oczi->rx_fis_dma);
	if (oczi->rx)
		dma_free_coherent(oczi->dev,
				  sizeof(*oczi->rx) * (OCZPCIE_RX_RING_SZ + 1),
				  oczi->rx, oczi->rx_dma);
	if (oczi->slot)
		dma_free_coherent(oczi->dev,
				  sizeof(*oczi->slot) * OCZPCIE_CHIP_SLOT_SZ,
				  oczi->slot, oczi->slot_dma);

	chip_iounmap(oczi);
	list_for_each_entry(mwq, &oczi->wq_list, entry)
		cancel_delayed_work(&mwq->work_q);
	kfree(oczi);
}

#ifndef	DISABLE_THREADED_INTERRUPTS
static irqreturn_t irq_check(int irq, void *param)
{
	struct oczpcie_prv_info *priv = param;
	struct oczpcie_info *oczi;
	int i;
	u32 core_nr;
	u32 stat;

	core_nr = priv->n_host;
	for (i = 0; i < core_nr; i++) {
		oczi = priv->oczi[i];
		stat = chip_isr_status(oczi, irq);
		if (stat) {
			chip_interrupt_disable(priv->oczi[0]);
			return IRQ_WAKE_THREAD;
		}
	}

	return IRQ_NONE;
}
#endif	// DISABLE_THREADED_INTERRUPTS

static irqreturn_t oczpcie_interrupt(int irq, void *param)
{
	struct oczpcie_prv_info *priv = param;
	u32 core_nr;
	u32 stat = 0;
	struct oczpcie_info *oczi;
	int handled = 0, work;
	u32 i;

	core_nr = priv->n_host;

	if (unlikely(!(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ)))
		chip_interrupt_disable(priv->oczi[0]);	// If we are not using threaded interrupts, need to stop new interrupts now

	for (i = 0; i < core_nr; i++) {
		oczi = priv->oczi[i];
		stat = chip_isr_status(oczi, irq);
		if (stat) {
			handled = 1;
			work = 1;
		}
		chip_isr(oczi, irq, stat);
	}

	chip_interrupt_enable(priv->oczi[0]); // enable for both threaded (disabled by irq_check) and non-threaded (disabled above)

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

static int oczpcie_alloc(struct oczpcie_info *oczi)
{
	int i = 0;
	char pool_name[32];

	spin_lock_init(&oczi->lock);
	for (i = 0; i < N_PHY; i++) {
		oczpcie_phy_init(oczi, i);
	}
	for (i = 0; i < N_PHY; i++) {
		oczi->devices[i].taskfileset = OCZPCIE_ID_NOT_MAPPED;
		oczi->devices[i].dev_type = NO_DEVICE;
		oczi->devices[i].device_id = i;
		oczi->devices[i].dev_status = OCZPCIE_DEV_NORMAL;
	}

	/*
	 * alloc and init our DMA areas
	 */
	oczi->tx = dma_alloc_coherent(oczi->dev,
				     sizeof(*oczi->tx) * OCZPCIE_CHIP_SLOT_SZ,
				     &oczi->tx_dma, GFP_KERNEL);
	if (!oczi->tx)
		goto err_out;
	memset(oczi->tx, 0, sizeof(*oczi->tx) * OCZPCIE_CHIP_SLOT_SZ);
	oczi->rx_fis = dma_alloc_coherent(oczi->dev, OCZPCIE_RX_FISL_SZ,
					 &oczi->rx_fis_dma, GFP_KERNEL);
	if (!oczi->rx_fis)
		goto err_out;
	memset(oczi->rx_fis, 0, OCZPCIE_RX_FISL_SZ);

	oczi->rx = dma_alloc_coherent(oczi->dev,
				     sizeof(*oczi->rx) * (OCZPCIE_RX_RING_SZ + 1),
				     &oczi->rx_dma, GFP_KERNEL);
	if (!oczi->rx)
		goto err_out;
	memset(oczi->rx, 0, sizeof(*oczi->rx) * (OCZPCIE_RX_RING_SZ + 1));
	oczi->rx[0] = cpu_to_le32(0xfff);
	oczi->rx_cons = 0xfff;

	oczi->slot = dma_alloc_coherent(oczi->dev,
				       sizeof(*oczi->slot) * OCZPCIE_CHIP_SLOT_SZ,
				       &oczi->slot_dma, GFP_KERNEL);
	if (!oczi->slot)
		goto err_out;
	memset(oczi->slot, 0, sizeof(*oczi->slot) * OCZPCIE_CHIP_SLOT_SZ);

	sprintf(pool_name, "%s%d", "oczpcie_dma_pool", oczi->id);
	oczi->dma_pool = pci_pool_create(pool_name, oczi->pdev, OCZPCIE_SLOT_BUF_SZ, 16, 0);
	if (!oczi->dma_pool) {
		goto err_out;
	}
	for (i = 0; i < N_PHY; i++) {
		oczi->devices[i].tags_num = MAX_NCQ_DEPTH;
		oczi->devices[i].tags = 0;
		oczpcie_tag_init(&oczi->devices[i]);
	}
	for (i = 0; i < (1L << SLOT_WIDTH); i++) {
		struct oczpcie_slot_info *slot = &oczi->slot_info[i];
		slot->buf = pci_pool_alloc(oczi->dma_pool, GFP_KERNEL, &slot->buf_dma);
		if (slot->buf == NULL) {
			int j;
			for (j = 0; j < i; j++) {
				slot = &oczi->slot_info[j];
				pci_pool_free(oczi->dma_pool, slot->buf, slot->buf_dma);
			}
			goto err_out;
		}
	}

	return 0;
err_out:
	return 1;
}

int oczpcie_ioremap(struct oczpcie_info *oczi, int bar, int bar_ex)
{
	unsigned long res_start, res_len, res_flag, res_flag_ex = 0;
	struct pci_dev *pdev = oczi->pdev;
	if (bar_ex != -1) {
		/*
		 * ioremap main and peripheral registers
		 */
		res_start = pci_resource_start(pdev, bar_ex);
		res_len = pci_resource_len(pdev, bar_ex);
		if (!res_start || !res_len)
			goto err_out;

		res_flag_ex = pci_resource_flags(pdev, bar_ex);
		if (res_flag_ex & IORESOURCE_MEM) {
			if (res_flag_ex & IORESOURCE_CACHEABLE)
				oczi->regs_ex = ioremap(res_start, res_len);
			else
				oczi->regs_ex = ioremap_nocache(res_start,
						res_len);
		} else
			oczi->regs_ex = (void *)res_start;
		if (!oczi->regs_ex)
			goto err_out;
	}

	res_start = pci_resource_start(pdev, bar);
	res_len = pci_resource_len(pdev, bar);
	if (!res_start || !res_len)
		goto err_out;

	res_flag = pci_resource_flags(pdev, bar);
	if (res_flag & IORESOURCE_CACHEABLE)
		oczi->regs = ioremap(res_start, res_len);
	else
		oczi->regs = ioremap_nocache(res_start, res_len);

	if (!oczi->regs) {
		if (oczi->regs_ex && (res_flag_ex & IORESOURCE_MEM))
			iounmap(oczi->regs_ex);
		oczi->regs_ex = NULL;
		goto err_out;
	}

	return 0;
err_out:
	return -1;
}

void oczpcie_iounmap(void __iomem *regs)
{
	iounmap(regs);
}

static struct oczpcie_info *oczpcie_pci_alloc(struct pci_dev *pdev,
				const struct pci_device_id *ent,
				struct oczpcie_prv_info *priv, unsigned int id)
{
	struct oczpcie_info *oczi = NULL;
	int i;

	oczi = kzalloc(sizeof(*oczi) +
		(1L << SLOT_WIDTH) *
		sizeof(struct oczpcie_slot_info), GFP_KERNEL);
	if (!oczi)
		return NULL;

	oczi->pdev = pdev;
	oczi->dev = &pdev->dev;
	INIT_LIST_HEAD(&oczi->wq_list);

	priv->oczi[id] = oczi;

	oczi->id = id;

	for (i = 0; i < N_PHY; i++) {
		INIT_LIST_HEAD(&oczi->task_queue[i]);
	}

	if (chip_ioremap(oczi))
		goto err_out;
	if (!oczpcie_alloc(oczi))
		return oczi;
err_out:
	oczpcie_free(oczi);
	return NULL;
}

static int enable_64_bit_pci(struct pci_dev *pdev)
{
	int rc;

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		rc = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (rc) {
			rc = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
			if (rc) {
				dev_printk(KERN_ERR, &pdev->dev,
					   "64-bit DMA enable failed\n");
				return rc;
			}
		}
	} else {
		rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				   "32-bit DMA enable failed\n");
			return rc;
		}
		rc = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				   "32-bit consistent DMA enable failed\n");
			return rc;
		}
	}

	return rc;
}

int oczpcie_get_dev_id_from_block_device(dev_t bd_bdev, struct request_queue *q, struct oczpcie_info **oczi)
{
	struct oczpcie_prv_info *mpi;
	u8 dev_id;

	dev_id = (MINOR(bd_bdev) >> PARTITION_SHIFT);

	mpi = (struct oczpcie_prv_info *)q->queuedata;
	*oczi = mpi->oczi[0];
	if (dev_id >= (*oczi)->n_phy) {
		dev_id -= (*oczi)->n_phy;
		*oczi = mpi->oczi[1];
		if (unlikely(dev_id >= (*oczi)->n_phy)) {
			return -1;
		}
	}

	return dev_id;
}

static int block_open(struct block_device *bdev, fmode_t mode)
{
	struct request_queue *q;
	struct oczpcie_prv_info *priv;

	if (unlikely(!disable_vca && !(mode & (FMODE_EXCL | FMODE_EXEC))))
		return -EPERM;

	q = bdev_get_queue(bdev);
	priv = (struct oczpcie_prv_info *)q->queuedata;
	kref_get(&priv->kref);
	return 0;
}

static void kref_free(struct kref *kref);

#if	LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static void block_close(struct gendisk *disk, fmode_t mode)
#else
static int block_close(struct gendisk *disk, fmode_t mode)
#endif
{
	struct oczpcie_prv_info *priv;

	priv = (struct oczpcie_prv_info *)disk->queue->queuedata;
	kref_put(&priv->kref, kref_free);
#if	LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	return;
#else
	return 0;
#endif
}

static int block_ioctl(struct block_device *dev, fmode_t mode, unsigned cmd, unsigned long arg)
{
	return oczpcie_ioctl(dev, mode, cmd, arg);
}

int oczpcie_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct oczpcie_info *oczi;
	int dev_id = oczpcie_get_dev_id_from_block_device(bdev->bd_dev, bdev_get_queue(bdev), &oczi);
	struct request_queue *q;
	struct oczpcie_prv_info *mpi;

	if (unlikely(dev_id == -1))
		return -ENODEV;

	q = bdev_get_queue(bdev);
	mpi = (struct oczpcie_prv_info *)q->queuedata;

	// Values assigned to deal with the size of fields in the hd_geometry structure 
	geo->heads     = 128;
	geo->sectors   = 128;
	geo->cylinders = get_capacity(mpi->disc[dev_id]) / (128*128);
	geo->start     = 0;
	return 0;
}

static struct block_device_operations block_ops =
{
		.owner = THIS_MODULE,
		.open = block_open,
		.release = block_close,
		.ioctl = block_ioctl,
		.getgeo = oczpcie_getgeo
};

static inline void send_or_queue_task(struct oczpcie_task *task)
{
	unsigned long flags = 0;
	struct oczpcie_info *oczi = task->oczi;
	struct oczpcie_prv_info *mpi = oczi->prv_info;

	if (likely(mpi->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_lock_bh(&oczi->lock);
	else
		spin_lock_irqsave(&oczi->lock, flags);

	// add to queue
	INIT_LIST_HEAD(&task->list);
	list_add_tail(&task->list, &oczi->task_queue[task->device_number]);
	// pull off the first entry, there must be at least one as we have just added
	task = list_first_entry(&oczi->task_queue[task->device_number], struct oczpcie_task, list);
	// if we manage to send it to the card, remove it from the queue
	if (oczpcie_queue_command(task, oczi) == 0) {
		list_del(&task->list);
	}

	if (likely(mpi->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_unlock_bh(&oczi->lock);
	else
		spin_unlock_irqrestore(&oczi->lock, flags);
}

static void block_complete(struct oczpcie_task *task)
{
	struct bio *bio = task->bio;
	int stat;

	stat = task->task_status.stat;
	if (unlikely(stat) && task->retry_count > 0) {
		// retry
		task->task_status.stat = 0;
		task->retry_count--;
		task->task_done = block_complete;
		oczpcie_make_request(task->oczi->prv_info, GFP_ATOMIC, bio, task->retry_count);
		kmem_cache_free(task->mpi->task_mem_cache, task);
		return;
	}
	kmem_cache_free(task->mpi->task_mem_cache, task);
	bio_endio(bio);
}

#define MAX_WAIT	100
static int down_with_timeout(struct semaphore *sem)
{
	int wait_count = 0;

	while (down_trylock(sem) && wait_count++ < MAX_WAIT) {
		// we don't want to wait forever, so try with a sleep
		msleep(wait_count < 3 ? 10 : 100);
	}
	if (wait_count >= MAX_WAIT)
		return -1;

	return 0;
}

static int issue_flush(struct oczpcie_prv_info *mpi, int dev_id)
{
	struct oczpcie_issue_command command_info;

	memset(&command_info, 0, sizeof(command_info));
	command_info.cmd = ATA_CMD_FLUSH_EXT;
	command_info.dev_id = dev_id;
	command_info.is_write = 1;
	sema_init(&command_info.sem, 0);

	if (likely(oczpcie_issue_command(mpi, GFP_NOIO, &command_info ) == 0)) {
		if (down_with_timeout(&command_info.sem)) {
			oczpcie_abort_issue_command(mpi, &command_info);
			return -1;
		}
	}
	return 0;
}

static int issue_discard(struct oczpcie_prv_info *mpi, struct bio *bio, int dev_id, u64 lba, int sectors)
{
	struct oczpcie_issue_command *command_info;
	u64 *data;
	int i;
	const int max_dsm_data_size = 512;	// single sector

	oczpcie_dprintk("Discard request for lba %llx, sectors %d\n", lba, sectors);

	if (mpi->prv_flags & PRV_FLAGS_NO_DISCARD)
		return -EOPNOTSUPP;	// disabled due to firmware version

	if (unlikely(lba + sectors > get_capacity(mpi->disc[dev_id]))) {
		oczpcie_printk(KERN_ERR "Bad discard request for device %d: lba %lld, sectors %d, limit %lld\n", dev_id, lba, sectors, (unsigned long long)get_capacity(mpi->disc[dev_id]));
		return -EIO;
	}

	command_info = kmalloc(sizeof(struct oczpcie_issue_command), GFP_NOIO);
	if (unlikely(!command_info))
		return -ENOMEM;
	memset(command_info, 0, sizeof(struct oczpcie_issue_command));

	if (unlikely((command_info->num_pages = alloc_seperate_pages(max_dsm_data_size, &command_info->data, GFP_NOIO)) < 1)) {
		kfree(command_info);
		return -ENOMEM;
	}

	data = page_address(command_info->data[0]);
	memset(data, 0, max_dsm_data_size);

	// convert to ATA DSM style format
	i = 0;
	while (i < max_dsm_data_size && sectors > 0) {
		u64 item;
		u64 this_nsects;

		this_nsects = sectors > 0xFFFF ? 0xFFFF : sectors;
		item = lba | (this_nsects << 48);
		*data++ = cpu_to_le64(item);
		sectors -= this_nsects;
		lba += this_nsects;
	}

	command_info->process_flags = auto_free;
	command_info->bio = bio;
	command_info->dev_id = dev_id;
	command_info->cmd = ATA_CMD_DSM;
	command_info->is_write = 1;
	command_info->use_dma = 1;
	command_info->features = ATA_DSM_TRIM;
	command_info->len = max_dsm_data_size;
	command_info->timeout = 120 * HZ;

	return oczpcie_issue_command(mpi, GFP_NOIO, command_info); // auto_free set, do so data and command_info will be freed for us
}

void oczpcie_make_request(struct oczpcie_prv_info *priv, int alloc_flags, struct bio *bio, int retry)
{
	int err = 0;
	struct oczpcie_info *oczi;
	struct oczpcie_task *task = NULL;
	int sectors;
	u64 lba;
	struct scatterlist *sg = NULL;
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	int segno;
	struct bio_vec *bvec, *bvprv = NULL;
#else
	struct bio_vec bvec, uninitialized_var(bvprv);
	struct bvec_iter iter;
	int first = 1;
#endif
	struct oczpcie_host_to_dev_fis *fis;
	int is_write = (bio->bi_opf & 1);
	int dev_id;
	int minor_id;
	int sg_no = 0;
	int length = 0, offset = 0, fua = 0;
	struct page *page = NULL;

	if (unlikely(priv == NULL)) {
		oczpcie_dprintk("No priv\n");
		err = -EIO;
		goto error;
	}

#ifdef	REQ_WRITE_SAME
	if (unlikely(bio->bi_opf & REQ_WRITE_SAME)) {
		err = -EIO;
		goto error;
	}
#endif


	oczi = priv->oczi[0];	// not strictly needed, but compiler gets upset otherwise
	dev_id = oczpcie_get_dev_id_from_block_device(bio_dev(bio),bio->bi_disk->queue, &oczi);
	if (unlikely(dev_id == -1)) {
			err = -ENODEV;
			goto error;
	}

	minor_id = MINOR(bio_dev(bio)) >> PARTITION_SHIFT;
	if (unlikely(driver_halted_on_error || ((1 << minor_id) & priv->errored_phys))) {
		err = -EIO;
		goto error;
	}

	sectors = bio_sectors(bio);
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	lba = bio->bi_sector;
#else
	lba = bio->bi_iter.bi_sector;
#endif

	// flush
#if defined(DISCARD_BARRIER) // for really, really old kernels
	if (unlikely(bio->bi_opf & (1 << BIO_RW_BARRIER))) {
		fua = 1;
		issue_flush(priv, minor_id);
		if (unlikely(sectors == 0)) {
			err = 0;
			goto error;
		}
	}
#elif	defined(RW_BARRIER)
	if (unlikely(bio->bi_opf & (1 << RW_BARRIER))) {
		fua = 1;
		issue_flush(priv, minor_id);
		if (unlikely(sectors == 0)) {
			err = 0;
			goto error;
		}
	}
#elif	defined(REQ_FLUSH)
	if (unlikely((bio->bi_opf & REQ_FLUSH))) {
		fua = 1;
		issue_flush(priv, minor_id);
		if (unlikely(sectors == 0)) {
			err = 0;
			goto error;
		}
	}
	if (unlikely(bio->bi_opf & REQ_FUA)) {
		fua = 1;
	}
#endif // defined(RW_BARRIER)

	// discard
#if defined(DISCARD_BARRIER)	// for really, really old kernels
	if (unlikely(bio->bi_opf & (1 << BIO_RW_DISCARD))) {
		err = issue_discard(priv, bio, minor_id, lba, sectors);
		if (unlikely(err))
			goto error;
		return;
	}
#elif	defined(BIO_DISCARD) // for old kernels
	if (unlikely(bio->bi_opf & BIO_DISCARD)) {
		err = issue_discard(priv, bio, minor_id, lba, sectors);
		if (unlikely(err))
			goto error;
		return;
	}
#elif	defined(REQ_DISCARD)
	if (unlikely(bio->bi_opf & REQ_DISCARD)) {
		err = issue_discard(priv, bio, minor_id, lba, sectors);
		if (unlikely(err))
			goto error;
		return;
	}
#endif	// defined(BIO_DISCARD)

	if (unlikely(bio_segments(bio)) < 1) {
		err = -EIO;
		goto error;
	}

	task = kmem_cache_alloc(priv->task_mem_cache, alloc_flags);
	if (unlikely(!task)) {
		err = -ENOMEM;
		goto error;
	}

	task->timeout = 0;
	task->device_number = dev_id;
	task->phy_id = oczi->phymap[dev_id];
	task->lba = lba;

	task->mpi = priv;
	task->oczi = oczi;
	task->retry_count = retry;

	if (sectors < 1) {
		err = -EIO;
		goto error;
	}

	if (unlikely(sectors && !lba_48_ok(lba, sectors))) {
		err = -ERANGE;
		goto error;
	}

	fis = &task->ata_task.fis;

	fis->fis_type = 0x27;	// host to device
	fis->flags = 1 << 7;		// opts and PM, bit 7 indicates command
//	fis->flags |= 1;	// port multiplier number
	fis->command = is_write ? ATA_CMD_FPDMA_WRITE : ATA_CMD_FPDMA_READ;
//	fis->command = ATA_CMD_READ;
	fis->features = sectors & 0xff;
	fis->lbal = lba & 0xff;
	fis->lbam = (lba >> 8) & 0xff;
	fis->lbah = (lba >> 16) & 0xff;
	fis->device = ATA_LBA;
	if (unlikely(fua))
		fis->device |= (1 << 7);	// bit 7 is FUA
	fis->lbal_exp = (lba >> 24) & 0xff;
	fis->lbam_exp = (lba >> 32) & 0xff;
	fis->lbah_exp = (lba >> 40) & 0xff;
	fis->features_exp = (sectors >> 8) & 0xff;
	fis->sector_count = 0;
	fis->sector_count_exp = 0;
	fis->_r_a = 0;
	fis->control = ATA_DRQ;
	fis->_r_b = 0;

	task->ata_task.retry_count = 2;
	task->ata_task.use_ncq = 1;
	task->ata_task.dma_xfer = 1;
	task->ata_task.set_affil_pol = 0;
	task->ata_task.stp_affil_pol = 0;
	task->ata_task.device_control_reg_update = 0;

	task->ata_task.atapi_packet[0] = 0;

	sg = kmalloc(sizeof(struct scatterlist) * bio_segments(bio), alloc_flags);
	if (unlikely(sg == NULL)) {
		err = -ENOMEM;
		goto error;
	}
	sg_init_table(sg, bio_segments(bio));
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio_for_each_segment(bvec, bio, segno) {
		int merged = 0;
#ifdef	BROKEN_PHYS_MERGE
		if (bvprv && biovec_phys_mergeable(bvprv, bvec)) {
#else // BROKEN_PHYS_MERGE
		if (bvprv && BIOVEC_PHYS_MERGEABLE(bvprv, bvec)) {
#endif // BROKEN_PHYS_MERGE
			length += bvec->bv_len;
			merged = 1;
		}
		else {
			page = bvec->bv_page;
			length = bvec->bv_len;
			offset = bvec->bv_offset;
		}
		sg_set_page(sg + (merged ? sg_no - 1 : sg_no), page, length, offset);
		if (!merged)
			sg_no++;

		bvprv = bvec;
	}
#else // LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio_for_each_segment(bvec, bio, iter) {
		int merged = 0;
		if (!first && BIOVEC_PHYS_MERGEABLE(&bvprv, &bvec)) {
			length += bvec.bv_len;
			merged = 1;
		}
		else {
			page = bvec.bv_page;
			length = bvec.bv_len;
			offset = bvec.bv_offset;
		}
		sg_set_page(sg + (merged ? sg_no - 1 : sg_no), page, length, offset);
		if (!merged)
			sg_no++;

		bvprv = bvec;
		first = 0;
	}
#endif // LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	task->scatter = sg;
	task->num_scatter = sg_no;
	task->total_xfer_len = sectors << 9;
	task->data_dir = is_write ? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE;
	task->task_done = block_complete;

	task->bio = bio;

	send_or_queue_task(task);

	return;

error:
	if (sg)
		kfree(sg);
	if (task)
		kmem_cache_free(priv->task_mem_cache, task);
	bio_endio(bio);
}

#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static void zero_bio(struct bio *bio)
{
	struct bio_vec *bvec;
	int segno;

	bio_for_each_segment(bvec, bio, segno) {
		memset(page_address(bvec->bv_page) + bvec->bv_offset, 0, bvec->bv_len);
	}
}
#else // LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static void zero_bio(struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_segment(bvec, bio, iter) {
		memset(page_address(bvec.bv_page) + bvec.bv_offset, 0, bvec.bv_len);
	}
}
#endif // LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)

#if	LINUX_VERSION_CODE <  KERNEL_VERSION(3,2,0)
static int make_request(struct request_queue *q, struct bio *bio)
#elif	LINUX_VERSION_CODE <  KERNEL_VERSION(4,14,0)
static void make_request(struct request_queue *q, struct bio *bio)
#else
static blk_qc_t make_request(struct request_queue *q, struct bio *bio)
#endif
{
	struct oczpcie_prv_info *priv;

	if (unlikely(!disable_vca)) {
		if (bio->bi_opf & 1) {
			bio_endio(bio);
			goto finished;
		}
		else {
			zero_bio(bio);
			bio_endio(bio);
			goto finished;
		}
	}

	priv = (struct oczpcie_prv_info *)q->queuedata;

	oczpcie_make_request(priv, GFP_NOIO, bio, DEFAULT_RETRIES);

finished:
#if	LINUX_VERSION_CODE <  KERNEL_VERSION(3,2,0)
	return 0;
#elif	LINUX_VERSION_CODE <  KERNEL_VERSION(4,14,0)
	return;
#else
	return BLK_QC_T_NONE;
#endif
}

static void command_complete(struct oczpcie_task *task)
{
	struct oczpcie_issue_command *command_info;

	command_info = task->dma_info.command_info;

	if (likely(command_info)) {
		int will_auto_free;

		will_auto_free = (command_info->process_flags & auto_free);
		command_info->private = NULL;
		if (!test_and_set_bit(0, &command_info->private_flags))
		{
			if (task->error_status)
				*(task->error_status) = task->task_status.stat;
			 if (unlikely(command_info->callback))
				 command_info->callback(command_info);
			 if (!will_auto_free)	// don't set semaphore on auto-free, caller can't wait anyway
				 up(task->dma_info.sem);
		}
		if (will_auto_free) {	// caller must allocate dynamically, so okay to touch command_info, as we are freeing it
			free_seperate_pages(command_info->data, command_info->num_pages);
			kfree(command_info);
		}
	}

	if (task->bio) {
		int stat = task->task_status.stat;
		bio_endio(task->bio);
	}
	kmem_cache_free(task->mpi->task_mem_cache, task);
}

void oczpcie_abort_issue_command(struct oczpcie_prv_info *priv, struct oczpcie_issue_command *command_info)
{
	struct oczpcie_task *task = command_info->private;
	unsigned long flags = 0;
	spinlock_t *lock;

	if (unlikely(task == NULL))
		return;

	lock = &task->oczi->lock;
	if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_lock_bh(lock);
	else
		spin_lock_irqsave(lock, flags);
	set_bit(0, &command_info->private_flags);
	task->dma_info.command_info = NULL;
	if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
		spin_unlock_bh(lock);
	else
		spin_unlock_irqrestore(lock, flags);
}

int oczpcie_issue_command(struct oczpcie_prv_info *mpi, int alloc_flags, struct oczpcie_issue_command *command_info)
{
	int err = 0;
	struct oczpcie_info *oczi = NULL;
	struct oczpcie_task *task = NULL;
	int sectors;
	struct scatterlist *sg = NULL;
	struct oczpcie_host_to_dev_fis *fis;
	int num_pages;
	int seg_no;
	int dev_id = command_info->dev_id;
	u64 lba = command_info->lba;

	oczi = mpi->oczi[0];
	if (dev_id >= oczi->n_phy) {
		dev_id -= oczi->n_phy;
		oczi = mpi->oczi[1];
		if (dev_id >= oczi->n_phy) {
			err = -EIO;
			goto error;
		}
	}
	task = kmem_cache_alloc(mpi->task_mem_cache, alloc_flags);
	if (unlikely(!task)) {
		err = -ENOMEM;
		goto error;
	}
	command_info->private = task;
	task->timeout = 0;
	task->device_number = dev_id;

	task->phy_id = oczi->phymap[dev_id];
	task->lba = lba;

	task->mpi = mpi;
	task->oczi = oczi;
	task->retry_count = DEFAULT_RETRIES;

	sectors = command_info->len >> 9;	// must be multiple of 512

	if (unlikely(sectors && !lba_48_ok(lba, sectors))) {
		err = -ERANGE;
		goto error;
	}

	fis = &task->ata_task.fis;


	fis->fis_type = 0x27;	// host to device
	fis->flags = 1 << 7;		// opts and PM, bit 7 indicates command
	//fis->flags |= 1;	// port multiplier number
	fis->command = command_info->cmd;
	fis->features = command_info->features;
	fis->lbal = command_info->lba & 0xff;
	fis->lbam = (lba >> 8) & 0xff;
	fis->lbah = (lba >> 16) & 0xff;
	fis->device = ATA_LBA;
	fis->lbal_exp = (lba >> 24) & 0xff;
	fis->lbam_exp = (lba >> 32) & 0xff;
	fis->lbah_exp = (lba >> 40) & 0xff;
	fis->features_exp = 0;
	fis->sector_count = sectors;
	fis->sector_count_exp = 0;
	fis->_r_a = 0;
	fis->control = command_info->control;
	fis->_r_b = 0;

	task->ata_task.retry_count = 2;
	task->ata_task.use_ncq = 0;	// note, can't process NCQ command anyway if non_queue is set
	task->ata_task.dma_xfer = command_info->use_dma;
	task->ata_task.set_affil_pol = 0;
	task->ata_task.stp_affil_pol = 0;
	task->ata_task.device_control_reg_update = 0;

	task->ata_task.atapi_packet[0] = 0;

	if (command_info->len > 0 && command_info->num_pages) {
		int len_left;

		num_pages = command_info->num_pages;

		sg = kmalloc(sizeof(struct scatterlist) * num_pages, alloc_flags);
		if (unlikely(sg == NULL)) {
			err = -ENOMEM;
			goto error;
		}
		sg_init_table(sg, num_pages);
		len_left = command_info->len;
		for (seg_no = 0; seg_no < num_pages; seg_no++) {
			sg_set_page(sg + seg_no, command_info->data[seg_no], len_left > PAGE_SIZE ? PAGE_SIZE : len_left, 0);
			len_left -= PAGE_SIZE;
		}

		task->scatter = sg;
		task->num_scatter = num_pages;
		task->total_xfer_len = command_info->len;
		task->data_dir = command_info->is_write ? PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE;
		task->dma_info.pages = command_info->data;
		task->dma_info.num_pages = num_pages;
	}
	else {
		task->scatter = NULL;
		task->num_scatter = 0;
		task->total_xfer_len = 0;
		task->dma_info.pages = NULL;
		task->dma_info.num_pages = 0;
	}

	task->task_done = command_complete;

	task->dma_info.is_write = command_info->is_write;
	task->dma_info.sem = &command_info->sem;
	task->error_status = &command_info->stat;
	task->dma_info.command_info = command_info;
	task->bio = command_info->bio;
	task->timeout = command_info->timeout;

	if (unlikely(command_info->process_flags & no_queue)) {
		unsigned long flags = 0;

		if (likely(mpi->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_lock_bh(&oczi->lock);
		else
			spin_lock_irqsave(&oczi->lock, flags);
		oczpcie_task_exec(task, 1, oczi);
		if (likely(mpi->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_unlock_bh(&oczi->lock);
		else
			spin_unlock_irqrestore(&oczi->lock, flags);
	}
	else
		send_or_queue_task(task);

	return 0;

error:
	if (sg)
		kfree(sg);
	if (task)
		kmem_cache_free(mpi->task_mem_cache, task);
	return err;
}

static void destroy_block_devices(struct oczpcie_prv_info *priv)
{
	int i;
	int n_devices = 0;

    if (likely(priv->block_major > 0)) {
    	if (priv->oczi[0])
    		n_devices += priv->oczi[0]->n_phy;
    	if (priv->oczi[1])
    		n_devices += priv->oczi[1]->n_phy;
    	for (i = 0; i < n_devices; i++) {
    		if (priv->disc[i] && priv->disc[i]->major) {
    			del_gendisk(priv->disc[i]);
    			put_disk(priv->disc[i]);
    		}
    	    if (likely(priv->block_queue[i]))
    	    	blk_cleanup_queue(priv->block_queue[i]);
    	    priv->disc[i] = NULL;
    	    priv->block_queue[i] = NULL;
    	}
		unregister_blkdev(priv->block_major, DRV_NAME);
    }
}

static int create_block_devices(struct oczpcie_prv_info *mpi)
{
	int i;
	int n_devices;
	struct pci_dev *pdev = mpi->oczi[0]->pdev;
	struct oczpcie_issue_command command_info;
	u64 sectors;

	if (unlikely(mpi->block_major))
		return 0;

	mpi->block_major = register_blkdev(0, DRV_NAME);

	if (mpi->block_major < 0) {
		oczpcie_printk("Could not create block device\n");
		return -ENOMEM;
	}

	n_devices = mpi->oczi[0]->n_phy + mpi->oczi[1]->n_phy;
	for (i = 0; i < n_devices; i++) {
		char ata_model[39];
		char ata_fw[9];
		u16 additional_support;
		int domain_nr;

		mpi->block_queue[i] = blk_alloc_queue(GFP_KERNEL);
		if (unlikely(!mpi->block_queue[i])) {
			destroy_block_devices(mpi);
			return -ENOMEM;
		}

		mpi->block_queue[i]->queuedata = mpi;
		blk_queue_flag_set(QUEUE_FLAG_NONROT, mpi->block_queue[i]);
		blk_queue_make_request(mpi->block_queue[i], make_request);	// do this first, it resets the limtis
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, mpi->block_queue[i]);
		blk_queue_max_hw_sectors(mpi->block_queue[i], MAX_SG_ENTRY * PAGE_SIZE * 2);
		/* max discard sectors is as follows:
		 * We use a single block of 512 bytes.
		 * Each DMS TRIM entry is 8 bytes made from 48-bit LBA and 16-bit size, max
		 * size for each entry 0xFFFF (65535) sectors. We can thus pack 512 / 8 = 64 entries in a request.
		 * 64 * 65535 = 4194240 sectors
		 */
		blk_queue_max_discard_sectors(mpi->block_queue[i], 4194240);
#ifndef	DISABLE_DISCARD_TUNING
		mpi->block_queue[i]->limits.discard_alignment = 512;
		mpi->block_queue[i]->limits.discard_granularity = 512;
#endif

		mpi->disc[i] = alloc_disk(16);
		if (unlikely(!mpi->disc[i])) {
			destroy_block_devices(mpi);
			return -ENOMEM;
		}
		mpi->disc[i]->major = mpi->block_major;
		mpi->disc[i]->first_minor = N_PARTITIONS * i;
		mpi->disc[i]->minors = N_PARTITIONS;
		mpi->disc[i]->fops = &block_ops;
		mpi->disc[i]->queue = mpi->block_queue[i];
		mpi->disc[i]->private_data = 0;
		domain_nr = pci_domain_nr(pdev->bus);
		if (disable_vca) {
			if (unlikely(domain_nr))
				snprintf(mpi->disc[i]->disk_name, 32, "oczpcie_%d_%d_%d_%d_ssd", domain_nr, pdev->bus->number, PCI_SLOT(pdev->devfn), i);
			else
				snprintf(mpi->disc[i]->disk_name, 32, "oczpcie_%d_%d_%d_ssd", pdev->bus->number, PCI_SLOT(pdev->devfn), i);
		}
		else {
			if (unlikely(domain_nr))
				snprintf(mpi->disc[i]->disk_name, 32, ".oczctl_%d_%d_%d_%d", domain_nr, pdev->bus->number, PCI_SLOT(pdev->devfn), i);
			else
				snprintf(mpi->disc[i]->disk_name, 32, ".oczctl_%d_%d_%d", pdev->bus->number, PCI_SLOT(pdev->devfn), i);
		}

		memset(&command_info, 0, sizeof(command_info));

		command_info.cmd = ATA_CMD_ID_ATA;
		command_info.num_pages = alloc_seperate_pages(512, &command_info.data, GFP_KERNEL);
		if (unlikely(command_info.num_pages < 0)) {
			destroy_block_devices(mpi);
			return -ENOMEM;
		}
		command_info.dev_id = i;
		command_info.features = 0;
		command_info.is_write = 0;
		command_info.use_dma = 1;
		command_info.lba = 0;
		command_info.len = 512;
		sema_init(&command_info.sem, 0);

		if (likely(oczpcie_issue_command(mpi, GFP_KERNEL, &command_info ) == 0)) {	// we need the name and size
			if (down_with_timeout(&command_info.sem)) {
				oczpcie_abort_issue_command(mpi, &command_info);
				dev_printk(KERN_ERR, mpi->oczi[0]->dev, "Timeout on identify, cannot start\n");
				goto identify_error;
			}
		}
		else
			goto identify_error;

		ata_get_string(ata_model, page_address(command_info.data[0]), 27, 45);
		ata_get_string(ata_fw, page_address(command_info.data[0]), 23, 26);
		sectors = ata_get_qword(page_address(command_info.data[0]), 100);
		free_seperate_pages(command_info.data, command_info.num_pages);
		if (disable_vca) {
			dev_printk(KERN_INFO, mpi->oczi[0]->dev, "Device %s, model %s, firmware revision %s, sectors %lld\n", mpi->disc[i]->disk_name, ata_model, ata_fw, sectors);
		}
		else {
			if (i == 0)
				dev_printk(KERN_INFO, mpi->oczi[0]->dev, "Model %s, firmware revision %s\n", ata_model, ata_fw);
		}
		if (check_firmware_version(mpi->oczi[0]->dev, ata_model, ata_fw)) {
			// firmware is not suitable for running discard
			dev_printk(KERN_WARNING, mpi->oczi[0]->dev, "Device %d: Firmware does not support discard, discard will be disabled, please update your firmware\n", i);
			mpi->prv_flags |= PRV_FLAGS_NO_DISCARD;
		}

		set_capacity(mpi->disc[i], sectors);
		add_disk(mpi->disc[i]); // may start getting called from here on
	}

	return 0;

identify_error:
	add_disk(mpi->disc[i]);
	destroy_block_devices(mpi);
	return -EINVAL;
}

static void add_new_card(struct oczpcie_prv_info *priv)
{
	struct oczpcie_card_info *entry;

	if (disable_vca)
		return;

	entry = kmalloc(sizeof(struct oczpcie_card_info), GFP_KERNEL);

	if (likely(entry)) {
		entry->priv = priv;
		list_add_tail(&entry->list, &card_list);
		if (register_card_add_callback) {
			struct pci_dev *pdev = priv->oczi[0]->pdev;
			(*register_card_add_callback)(priv, priv->oczi[0]->n_phy + priv->oczi[1]->n_phy, pci_domain_nr(pdev->bus),
					pdev->bus->number, PCI_SLOT(pdev->devfn));
		}
	}
}

static void remove_card(struct oczpcie_prv_info *priv)
{
	if (disable_vca)
		return;

	if (register_card_remove_callback)
		(*register_card_remove_callback)(priv);
}

#ifdef HAVE_KERNEL_TIMER_SETUP
void timer_callback(struct timer_list *t)
{
	struct oczpcie_prv_info *priv = from_timer(priv, t, timer);
#else
void timer_callback(unsigned long param)
{
	struct oczpcie_prv_info *priv = (struct oczpcie_prv_info *)param;
#endif
	int host, phy, slot, dev, tag, i;
	unsigned long flags = 0;
	unsigned long now = jiffies;
	struct oczpcie_device *device;

	for (host = 0; host < N_HOST; host++) {
		if (priv->oczi[host]) {
			struct oczpcie_info *oczi = priv->oczi[host];

			if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
				spin_lock_bh(&oczi->lock);
			else
				spin_lock_irqsave(&oczi->lock, flags);

			for (phy = 0; phy < N_PHY; phy++) {
				int was_okay;
				// If the PHY has not done anything, cancel all the commands on it.
				// If the PHY has activity, look for any stuck commands.
				if (oczi->timeout[phy] && time_after(now, oczi->timeout[phy])) {
					// PHY timeout
					dev_printk(KERN_ERR, oczi->dev, "Timeout on PHY %d, controller %d", oczi->phymap[phy], host);
					was_okay = (oczi->devices[phy].dev_status == OCZPCIE_DEV_NORMAL);
					oczi->devices[phy].dev_status = OCZPCIE_DEV_EH;
					device = &oczi->devices[phy];
					for (slot = 0; slot < (1L << SLOT_WIDTH); slot++) {
						if (oczi->slot_info[slot].device == device && oczi->slot_info[slot].task) {
							*(u32 *)oczi->slot_info[slot].response = cpu_to_le32(WDOG_TO);
							oczpcie_slot_complete(oczi, slot | RXQ_ERR | RXQ_SLOT_RESET);
							oczpcie_int_rx(oczi, 0);	// in case it completed
						}
					}
					if (was_okay) {
						oczpcie_diag_handle_ncq_error(oczi, &oczi->devices[phy]);
					}

				}
				else {
					// No PHY timeout, check commands
					for (dev = 0; dev < N_PHY; dev++) {
						device = &oczi->devices[dev];
						for (tag = 0; tag < MAX_NCQ_DEPTH; tag++) {
							if (device->timeout[tag]  && time_after(now, device->timeout[tag])) {
								if (device->timeout[tag]) {
									int slot_idx = calc_slot(dev, tag);
									if (oczi->slot_info[slot_idx].task) {
										*(u32 *)oczi->slot_info[slot_idx].response = cpu_to_le32(ACK_NAK_TO);
										device->dev_status = OCZPCIE_DEV_EH;
										oczpcie_slot_complete(oczi, slot_idx | RXQ_ERR);
										oczpcie_int_rx(oczi, 0);	// in case it completed
									}
									device->dev_status = OCZPCIE_DEV_NORMAL;
								}
							}
						}
					}
				}
				// give the queues a kick
				for (i = 0; i < MAX_NCQ_DEPTH; i++) {
					struct oczpcie_task *queue_task;

					if (list_empty(&oczi->task_queue[phy])) {
						break;
					}
					queue_task = list_first_entry(&oczi->task_queue[phy], struct oczpcie_task, list);
					// if we manage to send it to the card, remove it from the queue
					if (oczpcie_queue_command(queue_task, queue_task->oczi) == 0) {
						list_del(&queue_task->list);
					}
					else {
						break;
					}
				}
			}
			if (likely(priv->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
				spin_unlock_bh(&oczi->lock);
			else
				spin_unlock_irqrestore(&oczi->lock, flags);
		}
	}
	priv->timer.expires = jiffies + TIMER_TICK;

	add_timer(&priv->timer);
}

static int oczpcie_pci_init(struct pci_dev *pdev,
				  const struct pci_device_id *ent)
{
	unsigned int rc, nhost = 0;
	struct oczpcie_info *oczi;
	struct oczpcie_prv_info *mpi = NULL;
	struct oczpcie_config_data config_data;
	irq_handler_t irq_handler = oczpcie_interrupt;
	int i, bios_check_err;

	dev_printk(KERN_INFO, &pdev->dev,
		"oczpcie: driver version %s\n", DRV_VERSION);
	rc = pci_enable_device(pdev);
	if (rc)
		goto err_out_enable;

	pci_set_master(pdev);

	rc = pci_request_regions(pdev, DRV_NAME);
	if (rc)
		goto err_out_disable;

	rc = enable_64_bit_pci(pdev);
	if (rc)
		goto err_out_regions;

	mpi = kmalloc(sizeof(struct oczpcie_prv_info), GFP_KERNEL);

	if (!mpi) {
		rc = -ENOMEM;
		goto err_out_regions;
	}
	memset(mpi, 0, sizeof(struct oczpcie_prv_info));

	kref_init(&mpi->kref);
	mpi->n_host = N_HOST;
	pci_set_drvdata(pdev, mpi);

	// kernel keeps pointer to cache name, not a copy
	sprintf(mpi->task_mem_cache_name, "%s_%d_%d_%d", "task_cache", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn));
	mpi->task_mem_cache = kmem_cache_create(mpi->task_mem_cache_name, sizeof(struct oczpcie_task), 0, 0, NULL);
	if (unlikely(!mpi->task_mem_cache)) {
		rc = -ENOMEM;
		goto err_out_regions;
	}
	// create work queue for error handling
	sprintf(mpi->error_workqueue_name, "%s_%d_%d_%d", "oczpcie_eh", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn));
	mpi->error_workqueue = create_singlethread_workqueue(mpi->error_workqueue_name);
	if (unlikely(!mpi->error_workqueue)) {
		rc = -ENOMEM;
		goto err_out_regions;
	}
	spin_lock_init(&mpi->spi_lock);

	driver_halted_on_error = 0; // may be hotplug, allowed access to all non-errored cards

	do {
		oczi = oczpcie_pci_alloc(pdev, ent, mpi, nhost);
		if (!oczi) {
			rc = -ENOMEM;
			goto err_out_regions;
		}
		oczi->prv_info = mpi;
		if (oczpcie_spi_read_hha_info(mpi, &oczi->hba_info_param)) {
			dev_printk(KERN_WARNING, oczi->dev, "Card BIOS information is missing/invalid, defaults assumed\n");
		}

		rc = chip_init(oczi);
		if (rc) {
			oczpcie_free(oczi);
			goto err_out_regions;
		}
		for (i = 0; i < N_PHY; i++){
			chip_assign_specified_reg_set(oczi, i);
			oczi->devices[i].taskfileset = i;
		}
		nhost++;
	} while (nhost < N_HOST);

	rc = pci_enable_msi(pdev);
	if (rc != -1) {
		mpi->oczi[0]->flags |= MVF_FLAG_MSI;
#ifdef	DISABLE_THREADED_INTERRUPTS
		rc = request_irq(pdev->irq, irq_handler, IRQF_SHARED,
				DRV_NAME, mpi);
#else
		if (likely(disable_threaded_interrupts == 0)) {
			mpi->oczi[0]->flags |= MVF_FLAG_THREADED_IRQ;
			rc = request_threaded_irq(pdev->irq, irq_check, irq_handler, IRQF_SHARED,
				DRV_NAME, mpi);
		}
		else {
			dev_printk(KERN_WARNING, oczi->dev, "Threaded interrupts disabled\n");
			rc = request_irq(pdev->irq, irq_handler, IRQF_SHARED,
					DRV_NAME, mpi);
		}
#endif
	}
	else {
		rc = request_irq(pdev->irq, irq_handler, IRQF_SHARED,
				DRV_NAME, mpi);
	}
	if (rc)
		goto err_out_regions;

	chip_interrupt_enable(oczi);

	bios_check_err = 0;
	if (!disable_vca) {
		if (oczpcie_spi_read_config_info(mpi, &config_data)) {
			dev_printk(KERN_ERR, oczi->dev, "Card config information cannot be read\n");
			bios_check_err++;
		}
		if (strncmp(config_data.signature, "OCZ ", 4) != 0) {
			dev_printk(KERN_ERR, oczi->dev, "Card config information has incorrect signature\n");
			bios_check_err++;
		}
		// An error is indicated by *unsetting* bits in the error information, ~0 means no errors */
		if (config_data.error_flags != ~0) {
			dev_printk(KERN_ERR, oczi->dev, "Card config indicates drive has an error, flags %x\n", config_data.error_flags);
			bios_check_err++;
		}
		if (mpi->oczi[0]->n_phy + mpi->oczi[1]->n_phy != config_data.drive_cnt) {
			dev_printk(KERN_ERR, oczi->dev, "Card config indicates card should have %d controllers, but %d found\n", config_data.drive_cnt, mpi->oczi[0]->n_phy + mpi->oczi[1]->n_phy);
			bios_check_err++;
		}
		if (config_data.VCA_mode != VCA_FAST_MODE) {
			dev_printk(KERN_ERR, oczi->dev, "Unexpected VCA mode %d found\n", config_data.VCA_mode);
			bios_check_err++;
		}
	}
	if (bios_check_err) {
		if (override_checks) {
			printk("Detected %d check error(s), but continuing as checks have been overridden, drive configuration may be incorrect\n", bios_check_err);
		}
		else {
			goto err_out_regions;
		}
	}

	rc = create_block_devices(mpi);

	if (unlikely(rc)) {
		goto err_out_regions;
	}

	add_new_card(mpi);

#ifdef HAVE_KERNEL_TIMER_SETUP
	timer_setup(&mpi->timer, timer_callback, 0);
#else
	init_timer(&mpi->timer);
	mpi->timer.function = timer_callback;
	mpi->timer.data = (unsigned long)mpi;
#endif
	mpi->timer.expires = jiffies + TIMER_TICK;
	add_timer(&mpi->timer);

	return 0;

err_out_regions:
	for (i = 0; i < N_HOST; i++) {
		if (mpi->oczi[i]) {
			if (i == 0) {
				chip_interrupt_disable(mpi->oczi[i]);
				free_irq(mpi->oczi[i]->pdev->irq, mpi);
				if (mpi->oczi[0]->flags & MVF_FLAG_MSI) {
					pci_disable_msi(mpi->oczi[i]->pdev);
				}
			}
			kfree(mpi->oczi[i]);
		}
	}
	pci_release_regions(pdev);
	if (mpi) {
		if (mpi->task_mem_cache)
			kmem_cache_destroy(mpi->task_mem_cache);
		if (mpi->error_workqueue)
			destroy_workqueue(mpi->error_workqueue);
		kfree(mpi);
	}
err_out_disable:
	pci_disable_device(pdev);
err_out_enable:
	if (rc == 0)
		rc = -ENODEV;
	return rc;
}

static void flush_devices(struct oczpcie_prv_info *priv)
{
	int i;
	int n_devices = 0;

	if (priv->oczi[0])
		n_devices += priv->oczi[0]->n_phy;
	if (priv->oczi[1])
		n_devices += priv->oczi[1]->n_phy;
	for (i = 0; i < n_devices; i++) {
		struct oczpcie_issue_command command_info;

		if (unlikely(issue_flush(priv, i) == -1))
			dev_printk(KERN_ERR, priv->oczi[0]->dev, "Timeout on flush\n");

		memset(&command_info, 0, sizeof(command_info));

		command_info.dev_id = i;
		command_info.cmd = ATA_CMD_STANDBYNOW1;
		sema_init(&command_info.sem, 0);

		if (likely(oczpcie_issue_command(priv, GFP_NOIO, &command_info ) == 0)) {
			if (down_with_timeout(&command_info.sem)) {
				oczpcie_abort_issue_command(priv, &command_info);
				dev_printk(KERN_ERR, priv->oczi[0]->dev, "Timeout on standby\n");
			}
		}
	}
}

static int suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct oczpcie_prv_info *priv;

	priv = pci_get_drvdata(pdev);

	flush_devices(priv);
	priv->prv_flags |= PRV_FLAGS_CONTROLLER_PAUSED;       // don't allow any new commands

	chip_interrupt_disable(priv->oczi[0]);

	pci_save_state(pdev);
	pci_set_power_state(pdev, pci_choose_state(pdev, state));

	return 0;
}

static int resume(struct pci_dev *pdev)
{
	struct oczpcie_prv_info *priv;

	priv = pci_get_drvdata(pdev);

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);

	chip_interrupt_enable(priv->oczi[0]);

	oczpcie_reset_card(priv);
	priv->prv_flags &= ~PRV_FLAGS_CONTROLLER_PAUSED;       // allow commands again

	return 0;
}

void oczpcie_reset_card(struct oczpcie_prv_info *priv)
{
	int host, phy;

	for (host = 0; host < N_HOST; host++) {
		struct oczpcie_info *oczi = priv->oczi[host];
		oczi->phys_ready = 0;
		chip_init(oczi);
		oczi->tx_prod = 0;
		oczi->rx[0] = cpu_to_le32(0xfff);
		oczi->rx_cons = 0xfff;
		for (phy = 0; phy < N_PHY; phy++){
			chip_assign_specified_reg_set(oczi, phy);
			oczi->devices[phy].taskfileset = phy;
		}
	}
}

static void pci_remove(struct oczpcie_prv_info *priv)
{
	unsigned short core_nr, i = 0;
	struct oczpcie_info *oczi = NULL;
	struct pci_dev *pdev;

	core_nr = priv->n_host;
	oczi = priv->oczi[0];

	del_timer(&priv->timer);

	remove_card(priv);

	destroy_block_devices(priv);

	flush_devices(priv);

	flush_workqueue(priv->error_workqueue);

	chip_interrupt_disable(oczi);
	pdev = oczi->pdev;
	free_irq(pdev->irq, priv);
	if (priv->oczi[0]->flags & MVF_FLAG_MSI) {
		pci_disable_msi(pdev);
	}
	for (i = 0; i < core_nr; i++) {
		oczi = priv->oczi[i];
		oczpcie_free(oczi);
	}
	if (priv->task_mem_cache)
		kmem_cache_destroy(priv->task_mem_cache);
	if (priv->error_workqueue)
		destroy_workqueue(priv->error_workqueue);
	pci_set_drvdata(pdev, NULL);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	kfree(priv);
	return;
}

static void oczpcie_pci_remove(struct pci_dev *pdev)
{
	struct oczpcie_prv_info *priv = pci_get_drvdata(pdev);

	kref_put(&priv->kref, kref_free);
}

static void oczpcie_pci_shutdown(struct pci_dev *pdev)
{
	struct oczpcie_prv_info *priv = pci_get_drvdata(pdev);

	flush_devices(priv);
}

static void kref_free(struct kref *kref)
{
	struct oczpcie_prv_info *priv = container_of(kref, struct oczpcie_prv_info, kref);
	pci_remove(priv);
}


#ifndef	PCI_VENDOR_ID_OCZ
#define	PCI_VENDOR_ID_OCZ	0x1b85
#endif

static struct pci_device_id oczpcie_pci_table[] = {
	{ PCI_VDEVICE(OCZ, 0x1044)}, // Z-Drive
	{ PCI_VDEVICE(OCZ, 0x1084)}, // Z-Drive
	{ PCI_VDEVICE(OCZ, 0x1021)}, // RevoDrive 350
	{ PCI_VDEVICE(OCZ, 0x1041)}, // RevoDrive 350

	{ }	/* terminate list */
};

static struct pci_driver oczpcie_pci_driver = {
	.name		= DRV_NAME,
	.id_table	= oczpcie_pci_table,
	.probe		= oczpcie_pci_init,
	.remove		= oczpcie_pci_remove,
	.shutdown	= oczpcie_pci_shutdown,
	.suspend	= suspend,
	.resume		= resume
};

struct task_struct *oczpcie_th;
static int __init oczpcie_init(void)
{
	int rc;

	rc = pci_register_driver(&oczpcie_pci_driver);

	if (rc)
		goto err_out;

	if (!disable_vca) {
		rc = request_module_nowait("oczvca");
		if (rc != 0)
			printk(KERN_WARNING "VCA module could not be loaded, error %d", rc);
	}

	return 0;

err_out:
	return rc;
}

static void __exit oczpcie_exit(void)
{
	pci_unregister_driver(&oczpcie_pci_driver);

	while (!list_empty(&card_list)) {
		struct oczpcie_card_info *entry;
		entry = list_first_entry(&card_list, struct oczpcie_card_info, list);
		if (entry) {
			list_del(&entry->list);
			kfree(entry);
		}
	}
}

module_init(oczpcie_init);
module_exit(oczpcie_exit);

MODULE_AUTHOR("OCZ Storage Solutions http://ocz.com/enterprise/support");
#ifdef	DISABLE_THREADED_INTERRUPTS
MODULE_DESCRIPTION("Threaded interrupts disabled");
#endif
#ifdef	DISABLE_DISCARD_TUNING
MODULE_DESCRIPTION("Discard tuning disabled");
#endif
MODULE_DESCRIPTION(DRV_VERSION_CHK);
MODULE_DESCRIPTION("OCZ PCIe driver");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, oczpcie_pci_table);
