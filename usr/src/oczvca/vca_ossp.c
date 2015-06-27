/*
 * Copyright 2014 by OCZ Storage Solutions.  All rights reserved.  All
 * information contained herein is proprietary and confidential to OCZ Storage Solutions.
 * Any use, reproduction, or disclosure without the written
 * permission of OCZ Storage Solutions is prohibited.
 */

#include	<linux/kernel.h>
#include	<linux/fs.h>
#include	<linux/errno.h>
#include	<linux/types.h>
#include	<linux/vmalloc.h>
#include	<linux/genhd.h>
#include	<linux/hdreg.h>
#include	<linux/blkdev.h>
#include	<linux/module.h>
#include	<linux/delay.h>
#include	<linux/version.h>


#include	"/usr/src/oczpcie/version.h"

#ifndef	NO_MODULE_INFO
MODULE_LICENSE("OCZ");
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR("OCZ Storage Solutions http://ocz.com/enterprise/support");
#ifdef	DISABLE_DISCARD_TUNING
MODULE_DESCRIPTION("Discard tuning disabled");
#endif
MODULE_DESCRIPTION(DRV_VERSION_CHK);
MODULE_DESCRIPTION("OCZ VCA");
#endif

#ifndef	FUNC_PREFIX
#define	FUNC_PREFIX
#endif

#ifdef	NO_MODULE_INFO
void oczpcie_vca_ossp_printk(const char *const fmt, ...);
int oczpcie_vca_ossp_snprintf(char *str, size_t size, const char *format, ...);
#else
void oczpcie_vca_ossp_printk(const char *const fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

int oczpcie_vca_ossp_snprintf(char *str, size_t size, const char *fmt, ...)
{
	int ret;
	va_list args;

	va_start(args, fmt);
	ret = vsnprintf(str, size, fmt, args);
	va_end(args);

	return ret;
}
#endif

FUNC_PREFIX void oczpcie_vca_ossp_spin_lock_init(spinlock_t *lock)
{
	spin_lock_init(lock);
}

FUNC_PREFIX void *oczpcie_vca_ossp_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}

FUNC_PREFIX void oczpcie_vca_ossp_kfree(const void *objp)
{
	kfree(objp);
}

FUNC_PREFIX mempool_t *oczpcie_vca_ossp_mempool_create_kmalloc_pool(int min_nr, size_t size)
{
	return mempool_create_kmalloc_pool(min_nr,size);
}

FUNC_PREFIX void *oczpcie_vca_ossp_mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	return mempool_alloc(pool, gfp_mask);
}

FUNC_PREFIX void oczpcie_vca_ossp_mempool_destroy(mempool_t *pool)
{
	return mempool_destroy(pool);
}

FUNC_PREFIX void oczpcie_vca_ossp_mempool_free(void *element, mempool_t *pool)
{
	mempool_free(element, pool);
}

FUNC_PREFIX struct page *oczpcie_vca_ossp_alloc_page(gfp_t gfp_mask)
{
	return alloc_page(gfp_mask);
}

FUNC_PREFIX void oczpcie_vca_ossp_free_page(struct page *page)
{
	__free_page(page);
}

FUNC_PREFIX void *oczpcie_vca_ossp_get_page_address(struct page *page)
{
	return page_address(page);
}

FUNC_PREFIX void oczpcie_vca_ossp_memcpy(char *dest, char *src, int len)
{
	memcpy(dest, src, len);
}

FUNC_PREFIX int oczpcie_vca_ossp_copy_from_user(void *to, void *from, int len)
{
	return copy_from_user(to, from, len);
}

FUNC_PREFIX int oczpcie_vca_ossp_copy_to_user(void *to, void *from, int len)
{
	return copy_to_user(to, from, len);
}

#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
FUNC_PREFIX unsigned short oczpcie_vca_ossp_bio_segment_sub_length(struct bio *bio_src, unsigned int *resid, unsigned short start, int allow_equal)
{
	struct bio_vec *bv;
	unsigned short idx = 0;

	__bio_for_each_segment(bv, bio_src, idx, start) {
		if (allow_equal) {
			if (*resid <= bv->bv_len)
				break;
		}
		else {
			if (*resid < bv->bv_len)
				break;
		}
		*resid -= bv->bv_len;
	}
	return idx;
}
#else
FUNC_PREFIX unsigned short oczpcie_vca_ossp_bio_segment_sub_length(struct bio *bio_src, unsigned int *resid, unsigned short start, int allow_equal)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned short idx = 0;

	bio_for_each_segment(bv, bio_src, iter) {
		if (start > 0) {
			start--;
			idx++;
			continue;
		}
		if (allow_equal) {
			if (*resid <= bv.bv_len)
				return idx;
		}
		else {
			if (*resid < bv.bv_len)
				return idx;
		}
		*resid -= bv.bv_len;
		idx++;
	}
	return idx-1;
}
#endif

FUNC_PREFIX struct bio *oczpcie_vca_ossp_bio_alloc(int alloc_flags, unsigned int nr_iovecs)
{
	return bio_alloc(alloc_flags, nr_iovecs);
}

FUNC_PREFIX struct block_device *oczpcie_vca_ossp_bio_get_bdev(struct bio *bio)
{
	return bio->bi_bdev;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_bdev(struct bio *bio, struct block_device *bdev)
{
	bio->bi_bdev = bdev;
}

FUNC_PREFIX unsigned long oczpcie_vca_ossp_bio_get_rw(struct bio *bio)
{
	return bio->bi_rw;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_rw(struct bio *bio, unsigned long rw)
{
	bio->bi_rw = rw;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_flags(struct bio *bio, int flags)
{
	bio->bi_flags = flags;
}

FUNC_PREFIX sector_t oczpcie_vca_ossp_bio_get_sector(struct bio *bio)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	return bio->bi_sector;
#else
	return bio->bi_iter.bi_sector;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_sector(struct bio *bio, sector_t sector)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_sector = sector;
#else
	bio->bi_iter.bi_sector = sector;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_add_sector(struct bio *bio, sector_t sector)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_sector += sector;
#else
	bio->bi_iter.bi_sector += sector;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_mark_as_cloned(struct bio *bio)
{
	bio->bi_flags |= 1 << BIO_CLONED;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_vcnt(struct bio *bio, unsigned short vcnt)
{
	bio->bi_vcnt = vcnt;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_size(struct bio *bio, unsigned int size)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_size = size;
#else
	bio->bi_iter.bi_size = size;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_add_size(struct bio *bio, unsigned int size)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_size += size;
#else
	bio->bi_iter.bi_size += size;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_sub_size(struct bio *bio, unsigned int size)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_size -= size;
#else
	bio->bi_iter.bi_size -= size;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_idx(struct bio *bio, unsigned short idx)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	bio->bi_idx = idx;
#else
	bio->bi_iter.bi_idx = idx;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_next(struct bio *bio, struct bio *next)
{
	bio->bi_next = next;
}

FUNC_PREFIX struct bio *oczpcie_vca_ossp_bio_get_next(struct bio *bio)
{
	return bio->bi_next;
}

FUNC_PREFIX void *oczpcie_vca_ossp_bio_vec_address(struct bio *bio, int index)
{
	return &bio->bi_io_vec[index];
}

FUNC_PREFIX int oczpcie_vca_ossp_get_bio_vec_structure_size(void)
{
	return sizeof(struct bio_vec);
}

FUNC_PREFIX struct bio_vec *oczpcie_vca_ossp_get_bio_vec(struct bio *bio, int index)
{
	return &bio->bi_io_vec[index];
}

FUNC_PREFIX void oczpcie_vca_ossp_set_bio_vec(struct bio *bio, int index, struct bio_vec *v)
{
	bio->bi_io_vec[index] = *v;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_vec_inc_offset(struct bio *bio, int index, int offset)
{
	bio->bi_io_vec[index].bv_offset += offset;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_vec_dec_len(struct bio *bio, int index, int len)
{
	bio->bi_io_vec[index].bv_len -= len;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_vec_set_len(struct bio *bio, int index, int len)
{
	bio->bi_io_vec[index].bv_len = len;
}

FUNC_PREFIX int oczpcie_vca_ossp_bio_get_size(struct bio *bio)
{
#if	LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	return bio->bi_size;
#else
	return bio->bi_iter.bi_size;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_private(struct bio *bio, void *private)
{
	bio->bi_private = private;
}

FUNC_PREFIX void *oczpcie_vca_ossp_bio_get_private(struct bio *bio)
{
	return bio->bi_private;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_set_end_io(struct bio *bio, void (*func)(struct bio *bio, int error))
{
	bio->bi_end_io = func;
}

FUNC_PREFIX int oczpcie_vca_ossp_bio_is_valid_dir(struct bio *bio)
{
	switch (bio_data_dir(bio))
	{
		case READ:
		case READA:
		case WRITE:
			return true;
	}

	return false;
}

FUNC_PREFIX int oczpcie_vca_ossp_bio_is_discard(struct bio *bio)
{
#if defined(DISCARD_BARRIER)
        if(bio->bi_rw & (1 << BIO_RW_DISCARD))
        	return true;
#elif defined(BIO_DISCARD)
        if(bio->bi_rw & BIO_DISCARD)
        	return true;
#elif defined(REQ_DISCARD)
        if(bio->bi_rw & REQ_DISCARD)
        	return true;
#else
	return false;
#endif
	return false;
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_put(struct bio *bio)
{
	bio_put(bio);
}

FUNC_PREFIX void oczpcie_vca_ossp_bio_endio(struct bio *bio, int err)
{
	bio_endio(bio, err);
}

FUNC_PREFIX struct bio *oczpcie_vca_ossp_bio_clone(struct bio *bio, gfp_t gfp_mask)
{
	return bio_clone(bio, gfp_mask);
}

FUNC_PREFIX struct request_queue *oczpcie_vca_ossp_blk_alloc_queue(gfp_t gfp_mask)
{
	return blk_alloc_queue(gfp_mask);
}

FUNC_PREFIX void *oczpcie_vca_ossp_queue_get_queuedata(struct request_queue *q)
{
	return q->queuedata;
}

FUNC_PREFIX void oczpcie_vca_ossp_queue_set_queuedata(struct request_queue *q, void *data)
{
	q->queuedata = data;
}

FUNC_PREFIX struct request_queue *oczpcie_vca_ossp_bdev_get_queue(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);
	return q;
}

FUNC_PREFIX void *oczpcie_vca_ossp_bdev_get_queuedata(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);
	return q->queuedata;
}

FUNC_PREFIX int oczpcie_vca_ossp_call_ioctl(struct block_device *bdev, unsigned cmd, unsigned long arg)
{
	return bdev->bd_disk->fops->ioctl(bdev, FMODE_READ | FMODE_WRITE, cmd, arg);
}

FUNC_PREFIX void oczpcie_vca_ossp_atomic_set(atomic_t *t, int v)
{
	atomic_set(t, v);
}

FUNC_PREFIX void oczpcie_vca_ossp_atomic_inc(atomic_t *t)
{
	atomic_inc(t);
}

FUNC_PREFIX int oczpcie_vca_ossp_atomic_dec_and_test(atomic_t *t)
{
	return atomic_dec_and_test(t);
}

FUNC_PREFIX int oczpcie_vca_ossp_down_interruptible(struct semaphore *sem)
{
	return down_interruptible(sem);
}

FUNC_PREFIX void oczpcie_vca_ossp_set_geo_cylinders(struct hd_geometry * geo, sector_t cylinders)
{
	geo->heads     = 128;
	geo->sectors   = 128;
	geo->cylinders = cylinders;
	geo->start     = 0;
}

FUNC_PREFIX void oczpcie_vca_ossp_blk_queue_make_request(struct request_queue *q, make_request_fn *fn)
{
	blk_queue_make_request(q, fn);
}

FUNC_PREFIX void oczpcie_vca_ossp_blk_set_params(struct request_queue *q, int max_hw_sectors, int max_discard_sectors, int discard_zeros_data)
{
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	queue_flag_set_unlocked(QUEUE_FLAG_IO_STAT, q);
	blk_queue_max_hw_sectors(q, max_hw_sectors);
	blk_queue_max_discard_sectors(q, max_discard_sectors);
#ifndef	DISABLE_DISCARD_TUNING
	q->limits.discard_alignment = 512;
	q->limits.discard_granularity = 512;
	q->limits.discard_zeroes_data = discard_zeros_data;
#endif
}

FUNC_PREFIX int oczpcie_vca_ossp_discard_zeros_data(struct request_queue *q)
{
#ifndef	DISABLE_DISCARD_TUNING
	return q->limits.discard_zeroes_data;
#else
	return 0;
#endif
}

FUNC_PREFIX void oczpcie_vca_ossp_gendisk_set_params(struct gendisk *gd, int major, int first_minor, int minors, struct request_queue *q, struct block_device_operations *fops)
{
	gd->major = major;
	gd->first_minor = first_minor;
	gd->minors = minors;
	gd->fops = fops;
	gd->queue = q;
	gd->private_data = 0;
}

FUNC_PREFIX struct gendisk *oczpcie_vca_ossp_get_gendisk_from_block(struct block_device *bd)
{
	return bd->bd_disk;
}

FUNC_PREFIX void oczpcie_vca_ossp_gendisk_set_capacity(struct gendisk *gd, sector_t capacity)
{
	set_capacity(gd, capacity);
}

FUNC_PREFIX sector_t oczpcie_vca_ossp_gendisk_get_capacity(struct gendisk *gd)
{
	return get_capacity(gd);
}

FUNC_PREFIX int oczpcie_vca_ossp_register_blkdev(unsigned int major, const char *name)
{
	return register_blkdev(major, name);
}

FUNC_PREFIX void oczpcie_vca_ossp_unregister_blkdev(unsigned int major, const char *name)
{
	unregister_blkdev(major, name);
}

FUNC_PREFIX void oczpcie_vca_ossp_blk_cleanup_queue(struct request_queue *q)
{
	blk_cleanup_queue(q);
}

FUNC_PREFIX struct gendisk *oczpcie_vca_ossp_alloc_disk(int minors)
{
	return alloc_disk(minors);
}

FUNC_PREFIX void oczpcie_vca_ossp_del_gendisk(struct gendisk *disk)
{
	return del_gendisk(disk);
}

FUNC_PREFIX void oczpcie_vca_ossp_put_disk(struct gendisk *disk)
{
	put_disk(disk);
}

FUNC_PREFIX void oczpcie_vca_ossp_add_disk(struct gendisk *disk)
{
	add_disk(disk);
}

FUNC_PREFIX void *oczpcie_vca_ossp_disk_get_queue(struct gendisk *disk)
{
	return disk->queue;
}

FUNC_PREFIX void oczpcie_vca_ossp_kref_init(void *kref)
{
	kref_init(kref);
}
FUNC_PREFIX void oczpcie_vca_ossp_kref_get(void *kref)
{
	kref_get(kref);
}

FUNC_PREFIX void oczpcie_vca_ossp_kref_put(void *kref, void (*release)(struct kref *kref))
{
	kref_put(kref, release);
}

FUNC_PREFIX int oczpcie_vca_ossp_call_usermode(char *path, char **argv, char **envp)
{
	return call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC);
}

FUNC_PREFIX void oczpcie_vca_ossp_msleep(int time)
{
	msleep(time);
}

FUNC_PREFIX struct module *oczpcie_vca_ossp_this_module(void)
{
	return THIS_MODULE;
}

FUNC_PREFIX int oczpcie_vca_ossp_do_div(u64 *n, int base)
{
	return do_div(*n, base);
}

FUNC_PREFIX void oczpcie_vca_ossp_start_io_acct(spinlock_t *lock, struct bio *bio)
{
	struct gendisk *disk = bio->bi_bdev->bd_disk;
	if (blk_queue_io_stat(disk->queue)) {
		const int rw = bio_data_dir(bio);
		int cpu = part_stat_lock();
		unsigned long flags;
		spin_lock_irqsave(lock, flags);
		part_stat_inc(cpu, &disk->part0, ios[rw]);
		part_stat_add(cpu, &disk->part0, sectors[rw], bio_sectors(bio));
		part_inc_in_flight(&disk->part0, rw);
		spin_unlock_irqrestore(lock, flags);
		part_stat_unlock();
	}
}

FUNC_PREFIX void oczpcie_vca_ossp_end_io_acct(spinlock_t *lock, struct bio *bio, unsigned long start_time)
{
	struct gendisk *disk = bio->bi_bdev->bd_disk;
	if (blk_queue_io_stat(disk->queue)) {
		const int rw = bio_data_dir(bio);
		unsigned long duration = jiffies - start_time;
		int cpu = part_stat_lock();
		unsigned long flags;
		spin_lock_irqsave(lock, flags);
		part_stat_add(cpu, &disk->part0, ticks[rw], duration);
		part_dec_in_flight(&disk->part0, rw);
		spin_unlock_irqrestore(lock, flags);
		part_stat_unlock();
	}
}

FUNC_PREFIX unsigned long oczpcie_vca_ossp_get_jiffies(void)
{
	unsigned long ret = jiffies;
	if (unlikely(ret == 0)) // we avoid zero as it has a special meaning
		ret = 1;
	return ret;
}

FUNC_PREFIX void oczpcie_vca_ossp_list_add_tail(struct list_head *new, struct list_head *head)
{
	list_add_tail(new, head);
}

FUNC_PREFIX void oczpcie_vca_ossp_list_del(struct list_head *entry)
{
	list_del(entry);
}

#ifndef	NO_MODULE_INFO

static int __init ossp_vca_init(void)
{
	int oczpcie_vca_init(void);

	return oczpcie_vca_init();
}

static void __exit ossp_vca_exit(void)
{
	void oczpcie_vca_exit(void);

	oczpcie_vca_exit();
}

module_init(ossp_vca_init);
module_exit(ossp_vca_exit);

#endif
