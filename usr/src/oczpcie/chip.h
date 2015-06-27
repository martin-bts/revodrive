/*
 * chip.h
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


#ifndef CHIP_H_
#define CHIP_H_

enum VANIR_REVISION_ID {
	VANIR_A0_REV		= 0xA0,
	VANIR_B0_REV		= 0x01,
	VANIR_C0_REV		= 0x02,
	VANIR_C1_REV		= 0x03,
	VANIR_C2_REV		= 0xC2,
	VANIR_C3_REV		= 0xC3,
};

enum hw_registers {
	OCZPCIE_GBL_CTL		= 0x04,  /* global control */
	OCZPCIE_GBL_INT_STAT	= 0x00,  /* global irq status */
	OCZPCIE_GPL_INT_ENABLE	= 0x0C,
	OCZPCIE_GBL_PI		= 0x0C,  /* ports implemented bitmask */

	OCZPCIE_PHY_CTL		= 0x40,  /* SOC PHY Control */
	OCZPCIE_PORTS_IMP		= 0x9C,  /* SOC Port Implemented */

	OCZPCIE_GBL_PORT_TYPE	= 0xa0,  /* port type */

	OCZPCIE_CTL			= 0x100, /* SAS/SATA port configuration */
	OCZPCIE_PCS			= 0x104, /* SAS/SATA port control/status */
	OCZPCIE_CMD_LIST_LO		= 0x108, /* cmd list addr */
	OCZPCIE_CMD_LIST_HI		= 0x10C,
	OCZPCIE_RX_FIS_LO		= 0x110, /* RX FIS list addr */
	OCZPCIE_RX_FIS_HI		= 0x114,
	OCZPCIE_STP_REG_SET_0	= 0x118, /* STP/SATA Register Set Enable */
	OCZPCIE_STP_REG_SET_1	= 0x11C,
	OCZPCIE_TX_CFG		= 0x120, /* TX configuration */
	OCZPCIE_TX_LO		= 0x124, /* TX (delivery) ring addr */
	OCZPCIE_TX_HI		= 0x128,

	OCZPCIE_TX_PROD_IDX		= 0x12C, /* TX producer pointer */
	OCZPCIE_TX_CONS_IDX		= 0x130, /* TX consumer pointer (RO) */
	OCZPCIE_RX_CFG		= 0x134, /* RX configuration */
	OCZPCIE_RX_LO		= 0x138, /* RX (completion) ring addr */
	OCZPCIE_RX_HI		= 0x13C,
	OCZPCIE_RX_CONS_IDX		= 0x140, /* RX consumer pointer (RO) */

	OCZPCIE_INT_COAL		= 0x148, /* Int coalescing config */
	OCZPCIE_INT_COAL_TMOUT	= 0x14C, /* Int coalescing timeout */
	OCZPCIE_INT_STAT		= 0x150, /* Central int status */
	OCZPCIE_INT_MASK		= 0x154, /* Central int enable */
	OCZPCIE_INT_STAT_SRS_0	= 0x158, /* SATA register set status */
	OCZPCIE_INT_MASK_SRS_0	= 0x15C,
	OCZPCIE_INT_STAT_SRS_1	= 0x160,
	OCZPCIE_INT_MASK_SRS_1	= 0x164,
	OCZPCIE_NON_NCQ_ERR_0	= 0x168, /* SRS Non-specific NCQ Error */
	OCZPCIE_NON_NCQ_ERR_1	= 0x16C,
	OCZPCIE_CMD_ADDR		= 0x170, /* Command register port (addr) */
	OCZPCIE_CMD_DATA		= 0x174, /* Command register port (data) */
	OCZPCIE_MEM_PARITY_ERR	= 0x178, /* Memory parity error */

					 /* ports 1-3 follow after this */
	OCZPCIE_P0_INT_STAT		= 0x180, /* port0 interrupt status */
	OCZPCIE_P0_INT_MASK		= 0x184, /* port0 interrupt mask */
					 /* ports 5-7 follow after this */
	OCZPCIE_P4_INT_STAT		= 0x1A0, /* Port4 interrupt status */
	OCZPCIE_P4_INT_MASK		= 0x1A4, /* Port4 interrupt enable mask */

					 /* ports 1-3 follow after this */
	OCZPCIE_P0_SER_CTLSTAT	= 0x1D0, /* port0 serial control/status */
					 /* ports 5-7 follow after this */
	OCZPCIE_P4_SER_CTLSTAT	= 0x1E0, /* port4 serial control/status */

					 /* ports 1-3 follow after this */
	OCZPCIE_P0_CFG_ADDR		= 0x200, /* port0 phy register address */
	OCZPCIE_P0_CFG_DATA		= 0x204, /* port0 phy register data */
					 /* ports 5-7 follow after this */
	OCZPCIE_P4_CFG_ADDR		= 0x220, /* Port4 config address */
	OCZPCIE_P4_CFG_DATA		= 0x224, /* Port4 config data */

					 /* phys 1-3 follow after this */
	OCZPCIE_P0_VSR_ADDR		= 0x250, /* phy0 VSR address */
	OCZPCIE_P0_VSR_DATA		= 0x254, /* phy0 VSR data */
					 /* phys 1-3 follow after this */
					 /* multiplexing */
	OCZPCIE_P4_VSR_ADDR 	= 0x250, /* phy4 VSR address */
	OCZPCIE_P4_VSR_DATA 	= 0x254, /* phy4 VSR data */
	OCZPCIE_PA_VSR_ADDR		= 0x290, /* All port VSR addr */
	OCZPCIE_PA_VSR_PORT		= 0x294, /* All port VSR data */
	OCZPCIE_COMMAND_ACTIVE	= 0x300,
};

enum pci_cfg_registers {
	PCR_CMD	= 0x4,
	PCR_INTR = 0x3C,
	PCR_PHY_CTL		= 0x40,
	PCR_MSI_CTRL	= 0x50,
	PCR_PHY_CTL2		= 0x90,
	PCR_DEV_CTRL		= 0x78,
	PCR_LINK_CONTROL	= 0x80,
	PCR_LINK_STAT		= 0x82,

	OCZ_PCI_RD_REQ_SIZE  = 0x2000,
	OCZ_PCI_RD_REQ_MASK  = 0x00007000,
};

/*  SAS/SATA Vendor Specific Port Registers */
enum sas_sata_vsp_regs {
	VSR_PHY_STAT		= 0x00 * 4, /* Phy Interrupt Status */
	VSR_PHY_MODE1		= 0x01 * 4, /* phy Interrupt Enable */
	VSR_PHY_MODE2		= 0x02 * 4, /* Phy Configuration */
	VSR_PHY_MODE3		= 0x03 * 4, /* Phy Status */
	VSR_PHY_MODE4		= 0x04 * 4, /* Phy Counter 0 */
	VSR_PHY_MODE5		= 0x05 * 4, /* Phy Counter 1 */
	VSR_PHY_MODE6		= 0x06 * 4, /* Event Counter Control */
	VSR_PHY_MODE7		= 0x07 * 4, /* Event Counter Select */
	VSR_PHY_MODE8		= 0x08 * 4, /* Event Counter 0 */
	VSR_PHY_MODE9		= 0x09 * 4, /* Event Counter 1 */
	VSR_PHY_MODE10		= 0x0A * 4, /* Event Counter 2 */
	VSR_PHY_MODE11		= 0x0B * 4, /* Event Counter 3 */
	VSR_PHY_ACT_LED		= 0x0C * 4, /* Activity LED control */

	VSR_PHY_FFE_CONTROL	= 0x10C,
	VSR_PHY_DFE_UPDATE_CRTL	= 0x110,
	VSR_REF_CLOCK_CRTL	= 0x1A0,
};

enum chip_register_bits {
	PHY_MIN_SPP_PHYS_LINK_RATE_MASK = (0x7 << 8),
	PHY_MAX_SPP_PHYS_LINK_RATE_MASK = (0x7 << 12),
	PHY_NEG_SPP_PHYS_LINK_RATE_MASK_OFFSET = (16),
	PHY_NEG_SPP_PHYS_LINK_RATE_MASK =
			(0x3 << PHY_NEG_SPP_PHYS_LINK_RATE_MASK_OFFSET),
};

enum pci_interrupt_cause {
	/*  MAIN_IRQ_CAUSE (R10200) Bits*/
	IRQ_COM_IN_I2O_IOP0            = (1 << 0),
	IRQ_COM_IN_I2O_IOP1            = (1 << 1),
	IRQ_COM_IN_I2O_IOP2            = (1 << 2),
	IRQ_COM_IN_I2O_IOP3            = (1 << 3),
	IRQ_COM_OUT_I2O_HOS0           = (1 << 4),
	IRQ_COM_OUT_I2O_HOS1           = (1 << 5),
	IRQ_COM_OUT_I2O_HOS2           = (1 << 6),
	IRQ_COM_OUT_I2O_HOS3           = (1 << 7),
	IRQ_PCIF_TO_CPU_DRBL0          = (1 << 8),
	IRQ_PCIF_TO_CPU_DRBL1          = (1 << 9),
	IRQ_PCIF_TO_CPU_DRBL2          = (1 << 10),
	IRQ_PCIF_TO_CPU_DRBL3          = (1 << 11),
	IRQ_PCIF_DRBL0                 = (1 << 12),
	IRQ_PCIF_DRBL1                 = (1 << 13),
	IRQ_PCIF_DRBL2                 = (1 << 14),
	IRQ_PCIF_DRBL3                 = (1 << 15),
	IRQ_XOR_A                      = (1 << 16),
	IRQ_XOR_B                      = (1 << 17),
	IRQ_SAS_A                      = (1 << 18),
	IRQ_SAS_B                      = (1 << 19),
	IRQ_CPU_CNTRL                  = (1 << 20),
	IRQ_GPIO                       = (1 << 21),
	IRQ_UART                       = (1 << 22),
	IRQ_SPI                        = (1 << 23),
	IRQ_I2C                        = (1 << 24),
	IRQ_SGPIO                      = (1 << 25),
	IRQ_COM_ERR                    = (1 << 29),
	IRQ_I2O_ERR                    = (1 << 30),
	IRQ_PCIE_ERR                   = (1 << 31),
};

union reg_phy_cfg {
	u32 v;
	struct {
		u32 phy_reset:1;
		u32 sas_support:1;
		u32 sata_support:1;
		u32 sata_host_mode:1;
		/*
		 * bit 2: 6Gbps support
		 * bit 1: 3Gbps support
		 * bit 0: 1.5Gbps support
		 */
		u32 speed_support:3;
		u32 snw_3_support:1;
		u32 tx_lnk_parity:1;
		/*
		 * bit 5: G1 (1.5Gbps) Without SSC
		 * bit 4: G1 (1.5Gbps) with SSC
		 * bit 3: G2 (3.0Gbps) Without SSC
		 * bit 2: G2 (3.0Gbps) with SSC
		 * bit 1: G3 (6.0Gbps) without SSC
		 * bit 0: G3 (6.0Gbps) with SSC
		 */
		u32 tx_spt_phs_lnk_rate:6;
		/* 8h: 1.5Gbps 9h: 3Gbps Ah: 6Gbps */
		u32 tx_lgcl_lnk_rate:4;
		u32 tx_ssc_type:1;
		u32 sata_spin_up_spt:1;
		u32 sata_spin_up_en:1;
		u32 bypass_oob:1;
		u32 disable_phy:1;
		u32 rsvd:8;
	} u;
};

#define MAX_SG_ENTRY		255

struct oczpcie_prd_imt {
#ifndef __BIG_ENDIAN
	__le32			len:22;
	u8			_r_a:2;
	u8			misc_ctl:4;
	u8			inter_sel:4;
#else
	u32			inter_sel:4;
	u32			misc_ctl:4;
	u32			_r_a:2;
	u32			len:22;
#endif
};

struct oczpcie_prd {
	/* 64-bit buffer address */
	__le64			addr;
	/* 22-bit length */
	__le32			im_len;
} __attribute__ ((packed));

/*
 * these registers are accessed through port vendor
 * specific address/data registers
 */
enum sas_sata_phy_regs {
	GENERATION_1_SETTING		= 0x118,
	GENERATION_1_2_SETTING		= 0x11C,
	GENERATION_2_3_SETTING		= 0x120,
	GENERATION_3_4_SETTING		= 0x124,
};

#define SPI_CTRL_REG           	0xc800
#define SPI_ADDR_REG            	0xc804
#define SPI_WR_DATA_REG         0xc808
#define SPI_RD_DATA_REG         	0xc80c
#define SPI_CTRL_READ         	(1U << 2)
#define SPI_ADDR_VLD         	(1U << 1)
#define SPI_CTRL_SpiStart     	(1U << 0)

static inline int
oczpcie_ffc64(u64 v)
{
	u64 x = ~v;
	return x ? __ffs64(x) : -1;
}

#define r_reg_set_enable(i) \
	(((i) > 31) ? mr32(OCZPCIE_STP_REG_SET_1) : \
	mr32(OCZPCIE_STP_REG_SET_0))

#define w_reg_set_enable(i, tmp) \
	(((i) > 31) ? mw32(OCZPCIE_STP_REG_SET_1, tmp) : \
	mw32(OCZPCIE_STP_REG_SET_0, tmp))

#define mr32(reg)	readl(regs + reg)
#define mw32(reg, val)	writel((val), regs + reg)
#define mw32_f(reg, val)	do {			\
				mw32(reg, val);	\
				mr32(reg);	\
			} while (0)

#define iow32(reg, val) 	outl(val, (unsigned long)(regs + reg))
#define ior32(reg) 		inl((unsigned long)(regs + reg))
#define iow16(reg, val) 	outw((unsigned long)(val, regs + reg))
#define ior16(reg) 		inw((unsigned long)(regs + reg))
#define iow8(reg, val) 		outb((unsigned long)(val, regs + reg))
#define ior8(reg) 		inb((unsigned long)(regs + reg))

void chip_iounmap(struct oczpcie_info *mvi);
int chip_init(struct oczpcie_info *mvi);
void chip_interrupt_enable(struct oczpcie_info *mvi);
void chip_interrupt_disable(struct oczpcie_info *mvi);
void chip_clear_active_cmds(struct oczpcie_info *mvi);
void chip_non_spec_ncq_error(struct oczpcie_info *mvi);
void chip_fix_phy_info(struct oczpcie_info *mvi, int i);
int chip_oob_done(struct oczpcie_info *mvi, int i);
int chip_ioremap(struct oczpcie_info *mvi);
void chip_wait_for_active(struct oczpcie_info *oczi, u32 slot_idx);
void chip_command_active(struct oczpcie_info *mvi, u32 slot_idx);
void chip_free_reg_set(struct oczpcie_info *mvi, u8 *tfs);
void chip_issue_stop(struct oczpcie_info *mvi);
void chip_detect_porttype(struct oczpcie_info *mvi, int i);
void chip_clear_srs_irq(struct oczpcie_info *mvi, u8 reg_set, u8 clear_all);
void chip_phy_reset(struct oczpcie_info *mvi, u32 phy_id, int hard);
u8 chip_assign_reg_set(struct oczpcie_info *mvi, u8 *tfs);
void chip_assign_specified_reg_set(struct oczpcie_info *mvi, u8 set);
void chip_make_prd(struct scatterlist *scatter, int nr, void *prd);
void chip_fix_dma(struct oczpcie_info *mvi, u32 phy_mask,
				int buf_len, int from, void *prd);
u32 chip_isr_status(struct oczpcie_info *mvi, int irq);
irqreturn_t chip_isr(struct oczpcie_info *mvi, int irq, u32 stat);

static inline u32 oczpcie_cr32(struct oczpcie_info *mvi, u32 addr)
{
	void __iomem *regs = mvi->regs;

	mw32(OCZPCIE_CMD_ADDR, addr);
	return mr32(OCZPCIE_CMD_DATA);
}

static inline void oczpcie_cw32(struct oczpcie_info *mvi, u32 addr, u32 val)
{
	void __iomem *regs = mvi->regs;
	mw32(OCZPCIE_CMD_ADDR, addr);
	mw32(OCZPCIE_CMD_DATA, val);
}

static inline u32 oczpcie_read_phy_ctl(struct oczpcie_info *mvi, u32 port)
{
	void __iomem *regs = mvi->regs;
	return (port < 4) ? mr32(OCZPCIE_P0_SER_CTLSTAT + port * 4) :
		mr32(OCZPCIE_P4_SER_CTLSTAT + (port - 4) * 4);
}

static inline void oczpcie_write_phy_ctl(struct oczpcie_info *mvi, u32 port, u32 val)
{
	void __iomem *regs = mvi->regs;
	if (port < 4)
		mw32(OCZPCIE_P0_SER_CTLSTAT + port * 4, val);
	else
		mw32(OCZPCIE_P4_SER_CTLSTAT + (port - 4) * 4, val);
}

static inline u32 oczpcie_read_port(struct oczpcie_info *mvi, u32 off,
				u32 off2, u32 port)
{
	void __iomem *regs = mvi->regs + off;
	void __iomem *regs2 = mvi->regs + off2;
	return (port < 4) ? readl(regs + port * 8) :
		readl(regs2 + (port - 4) * 8);
}

static inline void oczpcie_write_port(struct oczpcie_info *mvi, u32 off, u32 off2,
				u32 port, u32 val)
{
	void __iomem *regs = mvi->regs + off;
	void __iomem *regs2 = mvi->regs + off2;
	if (port < 4)
		writel(val, regs + port * 8);
	else
		writel(val, regs2 + (port - 4) * 8);
}

static inline u32 oczpcie_read_port_cfg_data(struct oczpcie_info *mvi, u32 port)
{
	return oczpcie_read_port(mvi, OCZPCIE_P0_CFG_DATA,
			OCZPCIE_P4_CFG_DATA, port);
}

static inline void oczpcie_write_port_cfg_data(struct oczpcie_info *mvi,
						u32 port, u32 val)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_CFG_DATA,
			OCZPCIE_P4_CFG_DATA, port, val);
}

static inline void oczpcie_write_port_cfg_addr(struct oczpcie_info *mvi,
						u32 port, u32 addr)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_CFG_ADDR,
			OCZPCIE_P4_CFG_ADDR, port, addr);
	mdelay(10);
}

static inline u32 oczpcie_read_port_vsr_data(struct oczpcie_info *mvi, u32 port)
{
	return oczpcie_read_port(mvi, OCZPCIE_P0_VSR_DATA,
			OCZPCIE_P4_VSR_DATA, port);
}

static inline void oczpcie_write_port_vsr_data(struct oczpcie_info *mvi,
						u32 port, u32 val)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_VSR_DATA,
			OCZPCIE_P4_VSR_DATA, port, val);
}

static inline void oczpcie_write_port_vsr_addr(struct oczpcie_info *mvi,
						u32 port, u32 addr)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_VSR_ADDR,
			OCZPCIE_P4_VSR_ADDR, port, addr);
	mdelay(10);
}

static inline u32 oczpcie_read_port_irq_stat(struct oczpcie_info *mvi, u32 port)
{
	return oczpcie_read_port(mvi, OCZPCIE_P0_INT_STAT,
			OCZPCIE_P4_INT_STAT, port);
}

static inline void oczpcie_write_port_irq_stat(struct oczpcie_info *mvi,
						u32 port, u32 val)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_INT_STAT,
			OCZPCIE_P4_INT_STAT, port, val);
}

static inline u32 oczpcie_read_port_irq_mask(struct oczpcie_info *mvi, u32 port)
{
	return oczpcie_read_port(mvi, OCZPCIE_P0_INT_MASK,
			OCZPCIE_P4_INT_MASK, port);

}

static inline void oczpcie_write_port_irq_mask(struct oczpcie_info *mvi,
						u32 port, u32 val)
{
	oczpcie_write_port(mvi, OCZPCIE_P0_INT_MASK,
			OCZPCIE_P4_INT_MASK, port, val);
}

static inline void oczpcie_phy_hacks(struct oczpcie_info *mvi)
{
	u32 tmp;

	tmp = oczpcie_cr32(mvi, CMD_PHY_TIMER);
	tmp &= ~(1 << 9);
	tmp |= (1 << 10);
	oczpcie_cw32(mvi, CMD_PHY_TIMER, tmp);

	/* enable retry 127 times */
	oczpcie_cw32(mvi, CMD_SAS_CTL1, 0x7f7f);

	/* extend open frame timeout to max */
	tmp = oczpcie_cr32(mvi, CMD_SAS_CTL0);
	tmp &= ~0xffff;
	tmp |= 0x3fff;
	oczpcie_cw32(mvi, CMD_SAS_CTL0, tmp);

	oczpcie_cw32(mvi, CMD_WD_TIMER, 0x7a0000);

	/* not to halt for different port op during wideport link change */
	oczpcie_cw32(mvi, CMD_APP_ERR_CONFIG, 0xffefbf7d);
}

static inline void oczpcie_int_sata(struct oczpcie_info *mvi)
{
	u32 tmp;
	void __iomem *regs = mvi->regs;

	tmp = mr32(OCZPCIE_INT_STAT_SRS_0);
	if (tmp)
		mw32(OCZPCIE_INT_STAT_SRS_0, tmp);
}

static inline void oczpcie_int_full(struct oczpcie_info *mvi)
{
	void __iomem *regs = mvi->regs;
	u32 tmp, stat;
	int i;

	stat = mr32(OCZPCIE_INT_STAT);
	oczpcie_int_rx(mvi, false);

	for (i = 0; i < N_PHY; i++) {
		tmp = (stat >> i) & (CINT_PORT | CINT_PORT_STOPPED);
		if (tmp)
			oczpcie_int_port(mvi, i, tmp);
	}

	if (stat & CINT_SRS)
		oczpcie_int_sata(mvi);

	if (stat & CINT_NON_SPEC_NCQ_ERROR)
		chip_non_spec_ncq_error(mvi);

	mw32(OCZPCIE_INT_STAT, stat);
}

static inline void oczpcie_start_delivery(struct oczpcie_info *mvi, u32 tx)
{
	void __iomem *regs = mvi->regs;
	mw32(OCZPCIE_TX_PROD_IDX, tx);
}

static inline u32 oczpcie_rx_update(struct oczpcie_info *mvi)
{
	void __iomem *regs = mvi->regs;
	return mr32(OCZPCIE_RX_CONS_IDX);
}

static inline u32 oczpcie_get_prd_size(void)
{
	return sizeof(struct oczpcie_prd);
}

static inline u32 oczpcie_get_prd_count(void)
{
	return MAX_SG_ENTRY;
}

static inline void oczpcie_show_pcie_usage(struct oczpcie_info *mvi)
{
	u16 link_stat, link_spd;
	const char *spd[] = {
		"Unknown",
		"2.5",
		"5.0",
	};

	pci_read_config_word(mvi->pdev, PCR_LINK_STAT, &link_stat);
	link_spd = (link_stat & PLS_LINK_SPD) >> PLS_LINK_SPD_OFFS;
	if (link_spd >= 3)
		link_spd = 0;
	switch ((link_stat & PLS_NEG_LINK_WD)  >> PLS_NEG_LINK_WD_OFFS) {
		// adjust timing to work around HW having problems in 4 and 1 one lane slots
		case 8:
			mvi->interrupt_coalescing = 0x200;
			break;
		case 4:
			mvi->interrupt_coalescing = 0x300;
			break;
		default:
			mvi->interrupt_coalescing = 0x400;
			break;
	}

	if (mvi->id > 0)
		return;
	dev_printk(KERN_INFO, mvi->dev,
		"oczpcie: PCI-E x%u, Bandwidth Usage: %s Gbps\n",
	       (link_stat & PLS_NEG_LINK_WD) >> PLS_NEG_LINK_WD_OFFS,
	       spd[link_spd]);
}

#endif /* CHIP_H_ */
