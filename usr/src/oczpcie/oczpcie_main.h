/*
 * oczpcie_main.h
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

#ifndef _OCZPCIE_SAS_H_
#define _OCZPCIE_SAS_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/semaphore.h>
#include <linux/ata.h>
#include "defs.h"
#include "version.h"

#define DRV_NAME		"oczpcie"

//#define	OCZPCIE_DEBUG
#define OCZPCIE_ID_NOT_MAPPED	0x7f
#define WIDE_PORT_MAX_PHY		4
#define oczpcie_printk(fmt, arg ...)	\
	printk(KERN_DEBUG"%s %d:" fmt, __FILE__, __LINE__, ## arg)
#ifdef OCZPCIE_DEBUG
#define oczpcie_dprintk(format, arg...)	\
	printk(KERN_DEBUG"%s %d:" format, __FILE__, __LINE__, ## arg)
#else
#define oczpcie_dprintk(format, arg...)
#endif
#define OCZPCIE_MAX_U32			0xffffffff

#define DEV_IS_EXPANDER(type)	\
	((type == EDGE_DEV) || (type == FANOUT_DEV))

#define bit(n) ((u64)1 << n)

#define for_each_phy(__lseq_mask, __mc, __lseq)			\
	for ((__mc) = (__lseq_mask), (__lseq) = 0;		\
					(__mc) != 0 ;		\
					(++__lseq), (__mc) >>= 1)

#define OCZPCIE_INIT_DELAYED_WORK(w, f, d)	INIT_DELAYED_WORK(w, f)
#define UNASSOC_D2H_FIS(id)		\
	((void *) mvi->rx_fis + 0x100 * (id))
#define SATA_RECEIVED_FIS_LIST(reg_set)	\
	((void *) oczi->rx_fis + FIS_OFFS + 0x100 * (reg_set))
#define SATA_RECEIVED_SDB_FIS(reg_set)	\
	(SATA_RECEIVED_FIS_LIST(reg_set) + 0x58)
#define SATA_RECEIVED_D2H_FIS(reg_set)	\
	(SATA_RECEIVED_FIS_LIST(reg_set) + 0x40)
#define SATA_RECEIVED_PIO_FIS(reg_set)	\
	(SATA_RECEIVED_FIS_LIST(reg_set) + 0x20)
#define SATA_RECEIVED_DMA_FIS(reg_set)	\
	(SATA_RECEIVED_FIS_LIST(reg_set) + 0x00)

enum dev_status {
	OCZPCIE_DEV_NORMAL = 0x0,
	OCZPCIE_DEV_EH	= 0x1,
};

enum dev_reset {
	OCZPCIE_SOFT_RESET	= 0,
	OCZPCIE_HARD_RESET	= 1,
	OCZPCIE_PHY_TUNE	= 2,
};

struct oczpcie_info;

struct oczpcie_chip_info {
	u32 		n_host;
	u32 		n_phy;
	u32 		fis_offs;
	u32 		fis_count;
	u32 		srs_sz;
	u32 		slot_width;
};

#define OCZPCIE_MAX_SG		(1U << mvi->chip->sg_width)
#define OCZPCIE_CHIP_SLOT_SZ	(1U << SLOT_WIDTH)
/*
#define OCZPCIE_RX_FISL_SZ		\
	(mvi->chip->fis_offs + (mvi->chip->fis_count * 0x100))
*/
#define OCZPCIE_RX_FISL_SZ		\
	(FIS_OFFS + (FIS_COUNT * 0x100))
#define OCZPCIE_CHIP_DISP		(mvi->chip->dispatch)

struct oczpcie_err_info {
	__le32			flags;
	__le32			flags2;
};

struct oczpcie_cmd_hdr {
	__le32			flags;	/* PRD tbl len; SAS, SATA ctl */
	__le32			lens;	/* cmd, max resp frame len */
	__le32			tags;	/* targ port xfer tag; tag */
	__le32			data_len;	/* data xfer len */
	__le64			cmd_tbl;  	/* command table address */
	__le64			open_frame;	/* open addr frame address */
	__le64			status_buf;	/* status buffer address */
	__le64			prd_tbl;		/* PRD tbl address */
	__le32			reserved[4];
};

enum linkrate {
        LINK_RATE_UNKNOWN = 0,
        PHY_DISABLED = 1,
        PHY_RESET_PROBLEM = 2,
        SATA_SPINUP_HOLD = 3,
        SATA_PORT_SELECTOR = 4,
        PHY_RESET_IN_PROGRESS = 5,
        LINK_RATE_1_5_GBPS = 8,
        LINK_RATE_G1 = LINK_RATE_1_5_GBPS,
        LINK_RATE_3_0_GBPS = 9,
        LINK_RATE_G2 = LINK_RATE_3_0_GBPS,
        LINK_RATE_6_0_GBPS = 10,
        LINK_RATE_12_0_GBPS = 11
};


struct oczpcie_phy {
	struct oczpcie_info 		*oczi;
	struct scsi_device	*sdev;
	struct timer_list timer;
//	struct asd_sas_phy	sas_phy;
//	struct sas_identify     identify;
	u64		dev_sas_addr;
	u64		att_dev_sas_addr;
	u32		att_dev_info;
	u32		phy_type;
	u32		phy_status;
	u32		irq_status;
	u32		frame_rcvd_size;
	u8		frame_rcvd[32];
	u8		phy_attached;
	u8		phy_mode;
	u8		reserved[2];
	u32		phy_event;
    enum linkrate       minimum_linkrate;
    enum linkrate       maximum_linkrate;
};

enum device_flags {
	RUNNING_NON_NCQ = 1	// Device is running a non-NCQ command
};

struct oczpcie_device {
	struct list_head		dev_entry;
	int dev_type;
	struct oczpcie_info *mvi_info;
	struct domain_device *sas_device;
	u32 attached_phy;
	u32 device_id;
	int tags_num;
	u64 tags;	// good for up to NCQ depth of 63
	u32 running_req;
	unsigned long timeout[MAX_NCQ_DEPTH];	// per command timeouts
	u8 taskfileset;
	u8 dev_status;
	u16 flags;
};

/* Generate  PHY tunning parameters */
struct phy_tuning {
	/* 1 bit,  transmitter emphasis enable	*/
	u8	trans_emp_en:1;
	/* 4 bits, transmitter emphasis amplitude */
	u8	trans_emp_amp:4;
	/* 3 bits, reserved space */
	u8	Reserved_2bit_1:3;
	/* 5 bits, transmitter amplitude */
	u8	trans_amp:5;
	/* 2 bits, transmitter amplitude adjust */
	u8	trans_amp_adj:2;
	/* 1 bit, reserved space */
	u8	resv_2bit_2:1;
	/* 2 bytes, reserved space */
	u8	reserved[2];
};

struct ffe_control {
	/* 4 bits,  FFE Capacitor Select  (value range 0~F)  */
	u8 ffe_cap_sel:4;
	/* 3 bits,  FFE Resistor Select (value range 0~7) */
	u8 ffe_rss_sel:3;
	/* 1 bit reserve*/
	u8 reserved:1;
};

/*
 * HBA_Info_Page is saved in Flash/NVRAM, total 256 bytes.
 * The data area is valid only Signature="MRVL".
 * If any member fills with 0xFF, the member is invalid.
 */
struct hba_info_page {
	/* Dword 0 */
	/* 4 bytes, structure signature,should be "MRVL" at first initial */
	u8 signature[4];

	/* Dword 1-13 */
	u32 reserved1[13];

	/* Dword 14-29 */
	/* 64 bytes, SAS address for each port */
	u64 sas_addr[8];

	/* Dword 30-31 */
	/* 8 bytes for vanir 8 port PHY FFE seeting
	 * BIT 0~3 : FFE Capacitor select(value range 0~F)
	 * BIT 4~6 : FFE Resistor select(value range 0~7)
	 * BIT 7: reserve.
	 */

	struct ffe_control  ffe_ctl[8];
	/* Dword 32 -43 */
	u32 reserved2[12];

	/* Dword 44-45 */
	/* 8 bytes,  0:  1.5G, 1: 3.0G, should be 0x01 at first initial */
	u8 phy_rate[8];

	/* Dword 46-53 */
	/* 32 bytes, PHY tuning parameters for each PHY*/
	struct phy_tuning   phy_tuning[8];

	/* Dword 54-63 */
	u32 reserved3[10];
};	/* total 256 bytes */

#define	VCA_FAST_MODE	1
struct oczpcie_config_data {
	unsigned char   signature[4];       /*Offset 00h-03h*/
	unsigned char   version_major;      /*Offset 04h*/
	unsigned char   version_minor;      /*Offset 05h*/
	unsigned char   version_oem;        /*Offset 06h*/
	unsigned char   reserved_0;         /*Offset 07h*/
	unsigned char   product_id[4];      /*Offset 08h-0Bh*/
	unsigned char   VCA_mode;          /*Offset 0Ch*/
	unsigned char   drive_cnt;          /*Offset 0Dh*/
	unsigned char   drive_portmap;      /*Offset 0Eh*/
	unsigned char   reserved_1;         /*Offset 0Fh*/
	unsigned char   serial_numbers[160];/*Offset 10h-AFh*/  /*20bytes per serial number x 8 drives*/
	unsigned int    error_flags;        /*Offset B0h-B3h*/
	unsigned int    struct_checksum;    /*Offset B4h-B7h*/   /*NOTE: checksum needs to be at the end of the structure for current checksum functions to work correcly*/
};


struct oczpcie_slot_info {
	struct list_head entry;
	union {
		struct oczpcie_task *task;
		void *tdata;
	};
	u32 n_elem;
	u32 tx;
	u32 slot_tag;

	/* DMA buffer for storing cmd tbl, open addr frame, status buffer,
	 * and PRD table
	 */
	void *buf;
	dma_addr_t buf_dma;
	void *response;
	struct oczpcie_port *port;
	struct oczpcie_device *device;
};

// per-controller information, there are two controllers per card
struct oczpcie_info {
	unsigned long flags;

	// pointer back to the card private information
	struct oczpcie_prv_info *prv_info;

	/* host-wide lock */
	spinlock_t lock;

	/* our device */
	struct pci_dev *pdev;
	struct device *dev;

	/* enhanced mode registers */
	void __iomem *regs;

	/* peripheral or soc registers */
	void __iomem *regs_ex;

	/* TX (delivery) DMA ring */
	__le32 *tx;
	dma_addr_t tx_dma;

	/* cached next-producer idx */
	u32 tx_prod;

	/* RX (completion) DMA ring */
	__le32	*rx;
	dma_addr_t rx_dma;

	/* RX consumer idx */
	u32 rx_cons;

	/* RX'd FIS area */
	__le32 *rx_fis;
	dma_addr_t rx_fis_dma;

	/* DMA command header slots */
	struct oczpcie_cmd_hdr *slot;
	dma_addr_t slot_dma;

	int flash_type;	// SPI flash type
	int interrupt_coalescing;
//	const struct oczpcie_chip_info *chip;

	/* further per-slot information */
	struct oczpcie_phy phy[OCZPCIE_MAX_PHYS];
	u32 id;
	u64 sata_reg_set;
	struct list_head wq_list;
	u16 flashid;
	u32 flashsize;
	u32 flashsectSize;

	struct list_head task_queue[N_PHY];
	unsigned long timeout[N_PHY];
	u8 phymap[N_PHY];
	u8 n_phy;
	u8 phys_ready;

	struct hba_info_page hba_info_param;
	struct oczpcie_device	devices[N_PHY];
	void *dma_pool;
	struct oczpcie_slot_info slot_info[0];
};


static inline int calc_slot(int device, u8 tag)
{
	return (device << MAX_NCQ_DEPTH_SHIFT) | tag;
}

static inline int calc_device(struct oczpcie_info *oczi, int dev)
{
	int i;

	for (i = 0; i < oczi->id; i++) {
		dev += oczi->n_phy;
	}

	return dev;
}

enum prv_flags_values {
	PRV_FLAGS_NO_DISCARD = 1,
	PRV_FLAGS_CONTROLLER_PAUSED = 2
};

// driver private information, one per card
struct oczpcie_prv_info {
	u8 n_host;
	u8 scan_finished;
	u8 prv_flags;
	u8 errored_phys;
	struct oczpcie_info *oczi[2];
	int block_major;
	spinlock_t spi_lock;	// SPI flash lock
	struct kmem_cache *task_mem_cache;	// kmem_cache for oczpcie_task structures
	struct workqueue_struct *error_workqueue;	// work queue for handling error conditions
	char task_mem_cache_name[32];
	char error_workqueue_name[32];
	struct request_queue *block_queue[N_HOST * N_PHY];
	struct gendisk *disc[N_HOST * N_PHY];
	struct kref kref;	// reference count
	struct timer_list timer;
};

struct oczpcie_wq {
	struct delayed_work work_q;
	struct oczpcie_info *oczi;
	void *data;
	int handler;
	struct list_head entry;
};

struct oczpcie_task_exec_info {
	struct oczpcie_task *task;
	struct oczpcie_cmd_hdr *hdr;
	u32 tag;
	int n_elem;
};

enum issue_command_process_flags {
	auto_free = 1, // if auto_free is set, there can be no wait and the command_info and pages are auto-freed
	no_queue = 2 // issue to the command immediately, e.g. for error recovery, must NOT be an NCQ command
};

// issue command information
struct oczpcie_issue_command {
	struct oczpcie_task *private;	// used by issue_command, do not touch
	volatile long private_flags;			// used by issue_command, set to zero before calling, bit zero indicates
	int process_flags;
	struct bio *bio;	// if not NULL, the bio will be ended after the command, useful for non-data BIOs, such as discard
	int cmd;
	int dev_id;
	struct page **data;	// array of pages for data
	int num_pages;	// number of pages in above array
	int len;
	u64 lba;
	u64 timeout;
	int features;
	int control;
	int is_write;
	int use_dma;
	struct semaphore sem;
	void (*callback)(struct oczpcie_issue_command *);
	void *callback_param;
	int stat;

};


struct oczpcie_card_info {
	struct list_head list;
	struct oczpcie_prv_info *priv;
};

// chip functions
int chip_ioremap(struct oczpcie_info *mvi);

/******************** function prototype *********************/
void oczpcie_get_sas_addr(void *buf, u32 buflen);
void oczpcie_tag_clear(struct oczpcie_device *device, u32 tag);
void oczpcie_tag_free(struct oczpcie_device *device, u32 tag);
void oczpcie_tag_set(struct oczpcie_device *device, unsigned int tag);
int oczpcie_tag_alloc(struct oczpcie_device *device, u32 *tag_out,  int is_non_ncq);
void oczpcie_tag_init(struct oczpcie_device *device);
void oczpcie_iounmap(void __iomem *regs);
int oczpcie_ioremap(struct oczpcie_info *mvi, int bar, int bar_ex);
void oczpcie_phys_reset(struct oczpcie_info *mvi, u32 phy_mask, int hard);
void oczpcie_set_sas_addr(struct oczpcie_info *oczpcie_prv, int port_id,
				u32 off_lo, u32 off_hi, u64 sas_addr);
void oczpcie_scan_start(struct oczpcie_prv_info *oczpcie_prv);
int oczpcie_scan_finished(struct oczpcie_prv_info *oczpcie_prv, unsigned long time);
int oczpcie_task_exec(struct oczpcie_task *task, int is_tmf, struct oczpcie_info *oczi);
int oczpcie_queue_command(struct oczpcie_task *task, struct oczpcie_info *mvi);
int oczpcie_abort_task(struct oczpcie_task *task);
int oczpcie_abort_task_set(struct domain_device *dev, u8 *lun);
int oczpcie_clear_aca(struct domain_device *dev, u8 *lun);
int oczpcie_clear_task_set(struct domain_device *dev, u8 * lun);
void oczpcie_dev_gone(struct domain_device *dev);
int oczpcie_lu_reset(struct domain_device *dev, u8 *lun);
int oczpcie_slot_complete(struct oczpcie_info *mvi, u32 rx_desc);
int oczpcie_I_T_nexus_reset(struct domain_device *dev);
int oczpcie_query_task(struct oczpcie_task *task);
void oczpcie_int_port(struct oczpcie_info *mvi, int phy_no, u32 events);
void oczpcie_update_phyinfo(struct oczpcie_info *mvi, int i, int get_st);
int oczpcie_int_rx(struct oczpcie_info *mvi, bool self_clear);
struct oczpcie_device *oczpcie_find_dev_by_reg_set(struct oczpcie_info *mvi, u8 reg_set);
void oczpcie_set_sense(u8 *buffer, int len, int d_sense, int key, int asc, int ascq);
#endif

