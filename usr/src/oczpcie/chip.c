/*
 * chip.c
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

#include	"oczpcie_main.h"
#include	"chip.h"
#include	"diag.h"

void chip_detect_porttype(struct oczpcie_info *oczi, int i)
{
	u32 reg;
	struct oczpcie_phy *phy = &oczi->phy[i];
	u32 phy_status;

	oczpcie_write_port_vsr_addr(oczi, i, VSR_PHY_MODE3);
	reg = oczpcie_read_port_vsr_data(oczi, i);
	phy_status = ((reg & 0x3f0000) >> 16) & 0xff;
	phy->phy_type &= ~(PORT_TYPE_SAS | PORT_TYPE_SATA);
	switch (phy_status) {
	case 0x10:
		BUG_ON(1);
		phy->phy_type |= PORT_TYPE_SAS;
		break;
	case 0x1d:
	default:
		phy->phy_type |= PORT_TYPE_SATA;
		break;
	}
}

void set_phy_tuning(struct oczpcie_info *oczi, int phy_id,
			struct phy_tuning phy_tuning)
{
	u32 tmp, setting_0 = 0, setting_1 = 0;
	u8 i;

	/* Remap information for B0 chip:
	*
	* R0Ch -> R118h[15:0] (Adapted DFE F3 - F5 coefficient)
	* R0Dh -> R118h[31:16] (Generation 1 Setting 0)
	* R0Eh -> R11Ch[15:0]  (Generation 1 Setting 1)
	* R0Fh -> R11Ch[31:16] (Generation 2 Setting 0)
	* R10h -> R120h[15:0]  (Generation 2 Setting 1)
	* R11h -> R120h[31:16] (Generation 3 Setting 0)
	* R12h -> R124h[15:0]  (Generation 3 Setting 1)
	* R13h -> R124h[31:16] (Generation 4 Setting 0 (Reserved))
	*/

	/* A0 has a different set of registers */
	if (oczi->pdev->revision == VANIR_A0_REV)
		return;

	for (i = 0; i < 3; i++) {
		/* loop 3 times, set Gen 1, Gen 2, Gen 3 */
		switch (i) {
		case 0:
			setting_0 = GENERATION_1_SETTING;
			setting_1 = GENERATION_1_2_SETTING;
			break;
		case 1:
			setting_0 = GENERATION_1_2_SETTING;
			setting_1 = GENERATION_2_3_SETTING;
			break;
		case 2:
			setting_0 = GENERATION_2_3_SETTING;
			setting_1 = GENERATION_3_4_SETTING;
			break;
		}

		/* Set:
		*
		* Transmitter Emphasis Enable
		* Transmitter Emphasis Amplitude
		* Transmitter Amplitude
		*/
		oczpcie_write_port_vsr_addr(oczi, phy_id, setting_0);
		tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
		tmp &= ~(0xFBE << 16);
		tmp |= (((phy_tuning.trans_emp_en << 11) |
			(phy_tuning.trans_emp_amp << 7) |
			(phy_tuning.trans_amp << 1)) << 16);
		oczpcie_write_port_vsr_data(oczi, phy_id, tmp);

		/* Set Transmitter Amplitude Adjust */
		oczpcie_write_port_vsr_addr(oczi, phy_id, setting_1);
		tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
		tmp &= ~(0xC000);
		tmp |= (phy_tuning.trans_amp_adj << 14);
		oczpcie_write_port_vsr_data(oczi, phy_id, tmp);
	}
}

void set_phy_ffe_tuning(struct oczpcie_info *oczi, int phy_id,
				struct ffe_control ffe)
{
	u32 tmp;

	/* Don't run this if A0/B0 */
	if ((oczi->pdev->revision == VANIR_A0_REV)
		|| (oczi->pdev->revision == VANIR_B0_REV))
		return;

	/* FFE Resistor and Capacitor */
	/* R10Ch DFE Resolution Control/Squelch and FFE Setting
	 *
	 * FFE_FORCE            [7]
	 * FFE_RES_SEL          [6:4]
	 * FFE_CAP_SEL          [3:0]
	 */
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_PHY_FFE_CONTROL);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	tmp &= ~0xFF;

	/* Read from HBA_Info_Page */
	tmp |= ((0x1 << 7) |
		(ffe.ffe_rss_sel << 4) |
		(ffe.ffe_cap_sel << 0));

	oczpcie_write_port_vsr_data(oczi, phy_id, tmp);

	/* R064h PHY Mode Register 1
	 *
	 * DFE_DIS		18
	 */
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_REF_CLOCK_CRTL);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	tmp &= ~0x40001;
	/* Hard coding */
	/* No defines in HBA_Info_Page */
	tmp |= (0 << 18);
	oczpcie_write_port_vsr_data(oczi, phy_id, tmp);

	/* R110h DFE F0-F1 Coefficient Control/DFE Update Control
	 *
	 * DFE_UPDATE_EN        [11:6]
	 * DFE_FX_FORCE         [5:0]
	 */
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_PHY_DFE_UPDATE_CRTL);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	tmp &= ~0xFFF;
	/* Hard coding */
	/* No defines in HBA_Info_Page */
	tmp |= ((0x3F << 6) | (0x0 << 0));
	oczpcie_write_port_vsr_data(oczi, phy_id, tmp);

	/* R1A0h Interface and Digital Reference Clock Control/Reserved_50h
	 *
	 * FFE_TRAIN_EN         3
	 */
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_REF_CLOCK_CRTL);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	tmp &= ~0x8;
	/* Hard coding */
	/* No defines in HBA_Info_Page */
	tmp |= (0 << 3);
	oczpcie_write_port_vsr_data(oczi, phy_id, tmp);
}

/*Notice: this function must be called when phy is disabled*/
void set_phy_rate(struct oczpcie_info *oczi, int phy_id, u8 rate)
{
	union reg_phy_cfg phy_cfg, phy_cfg_tmp;
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_PHY_MODE2);
	phy_cfg_tmp.v = oczpcie_read_port_vsr_data(oczi, phy_id);
	phy_cfg.v = 0;
	phy_cfg.u.disable_phy = phy_cfg_tmp.u.disable_phy;
	phy_cfg.u.sas_support = 1;
	phy_cfg.u.sata_support = 1;
	phy_cfg.u.sata_host_mode = 1;

	switch (rate) {
	case 0x0:
		/* support 1.5 Gbps */
		phy_cfg.u.speed_support = 1;
		phy_cfg.u.snw_3_support = 0;
		phy_cfg.u.tx_lnk_parity = 1;
		phy_cfg.u.tx_spt_phs_lnk_rate = 0x30;
		break;
	case 0x1:

		/* support 1.5, 3.0 Gbps */
		phy_cfg.u.speed_support = 3;
		phy_cfg.u.tx_spt_phs_lnk_rate = 0x3c;
		phy_cfg.u.tx_lgcl_lnk_rate = 0x08;
		break;
	case 0x2:
	default:
		/* support 1.5, 3.0, 6.0 Gbps */
		phy_cfg.u.speed_support = 7;
		phy_cfg.u.snw_3_support = 1;
		phy_cfg.u.tx_lnk_parity = 1;
		phy_cfg.u.tx_spt_phs_lnk_rate = 0x3f;
		phy_cfg.u.tx_lgcl_lnk_rate = 0x09;
		break;
	}
	oczpcie_write_port_vsr_data(oczi, phy_id, phy_cfg.v);
}

static void
oczpcie_config_reg_from_hba(struct oczpcie_info *oczi, int phy_id)
{
	u32 temp;
	temp = (u32)(*(u32 *)&oczi->hba_info_param.phy_tuning[phy_id]);
	if (temp == 0xFFFFFFFFL) {
		oczi->hba_info_param.phy_tuning[phy_id].trans_emp_amp = 0x6;
		oczi->hba_info_param.phy_tuning[phy_id].trans_amp = 0x1A;
		oczi->hba_info_param.phy_tuning[phy_id].trans_amp_adj = 0x3;
	}

	temp = (u8)(*(u8 *)&oczi->hba_info_param.ffe_ctl[phy_id]);
	// BIOS bug, the entries for ffe are not valid, always use defaults
	switch (oczi->pdev->revision) {
		case VANIR_A0_REV:
		case VANIR_B0_REV:
			oczi->hba_info_param.ffe_ctl[phy_id].ffe_rss_sel = 0x7;
			oczi->hba_info_param.ffe_ctl[phy_id].ffe_cap_sel = 0x7;
			break;
		case VANIR_C0_REV:
		case VANIR_C1_REV:
		case VANIR_C2_REV:
		case VANIR_C3_REV:
		default:
			oczi->hba_info_param.ffe_ctl[phy_id].ffe_rss_sel = 0x7;
			oczi->hba_info_param.ffe_ctl[phy_id].ffe_cap_sel = 0xC;
			break;
	}

	temp = (u8)(*(u8 *)&oczi->hba_info_param.phy_rate[phy_id]);
	if (temp == 1)	// BIOS bug in some older versions, says 3G, should be 6G
		oczi->hba_info_param.phy_rate[phy_id] = 2;
	if (temp == 0xFFL)
		/*set default phy_rate = 6Gbps*/
		oczi->hba_info_param.phy_rate[phy_id] = 0x2;

	set_phy_tuning(oczi, phy_id,
		oczi->hba_info_param.phy_tuning[phy_id]);
	set_phy_ffe_tuning(oczi, phy_id,
		oczi->hba_info_param.ffe_ctl[phy_id]);
	set_phy_rate(oczi, phy_id,
		oczi->hba_info_param.phy_rate[phy_id]);
}

static void oczpcie_enable_xmt(struct oczpcie_info *oczi, int phy_id)
{
	void __iomem *regs = oczi->regs;
	u32 tmp;

	tmp = mr32(OCZPCIE_PCS);
	tmp |= 1 << (phy_id + PCS_EN_PORT_XMT_SHIFT2);
	mw32(OCZPCIE_PCS, tmp);
}

void chip_phy_reset(struct oczpcie_info *oczi, u32 phy_id, int hard)
{
	u32 tmp;
	u32 delay = 5000;
	if (hard == OCZPCIE_PHY_TUNE) {
		oczpcie_write_port_cfg_addr(oczi, phy_id, PHYR_SATA_CTL);
		tmp = oczpcie_read_port_cfg_data(oczi, phy_id);
		oczpcie_write_port_cfg_data(oczi, phy_id, tmp|0x20000000);
		oczpcie_write_port_cfg_data(oczi, phy_id, tmp|0x100000);
		return;
	}
	tmp = oczpcie_read_port_irq_stat(oczi, phy_id);
	tmp &= ~PHYEV_RDY_CH;
	oczpcie_write_port_irq_stat(oczi, phy_id, tmp);
	if (hard) {
		tmp = oczpcie_read_phy_ctl(oczi, phy_id);
		tmp |= PHY_RST_HARD;
		oczpcie_write_phy_ctl(oczi, phy_id, tmp);
		do {
			tmp = oczpcie_read_phy_ctl(oczi, phy_id);
			udelay(10);
			delay--;
		} while ((tmp & PHY_RST_HARD) && delay);
		if (!delay)
			oczpcie_dprintk("phy hard reset failed.\n");
	} else {
		tmp = oczpcie_read_phy_ctl(oczi, phy_id);
		tmp |= PHY_RST;
		oczpcie_write_phy_ctl(oczi, phy_id, tmp);
	}
}

static void oczpcie_phy_disable(struct oczpcie_info *oczi, u32 phy_id)
{
	u32 tmp;
	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_PHY_MODE2);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	oczpcie_write_port_vsr_data(oczi, phy_id, tmp | 0x00800000);
}

static void oczpcie_phy_enable(struct oczpcie_info *oczi, u32 phy_id)
{
	u32 tmp;
	u8 revision = 0;

	revision = oczi->pdev->revision;
	if (revision == VANIR_A0_REV) {
		oczpcie_write_port_vsr_addr(oczi, phy_id, CMD_HOST_RD_DATA);
		oczpcie_write_port_vsr_data(oczi, phy_id, 0x8300ffc1);
	}
	if (revision == VANIR_B0_REV) {
		oczpcie_write_port_vsr_addr(oczi, phy_id, CMD_APP_MEM_CTL);
		oczpcie_write_port_vsr_data(oczi, phy_id, 0x08001006);
		oczpcie_write_port_vsr_addr(oczi, phy_id, CMD_HOST_RD_DATA);
		oczpcie_write_port_vsr_data(oczi, phy_id, 0x0000705f);
	}

	oczpcie_write_port_vsr_addr(oczi, phy_id, VSR_PHY_MODE2);
	tmp = oczpcie_read_port_vsr_data(oczi, phy_id);
	tmp |= bit(0);
	oczpcie_write_port_vsr_data(oczi, phy_id, tmp & 0xfd7fffff);
}

int chip_init(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs;
	int i;
	u32 tmp, cctl;
	u8 revision;

	revision = oczi->pdev->revision;

	// Disable ASPM, it is known that some system boards have trouble with this
	tmp = pci_read_config_dword(oczi->pdev, PCR_LINK_CONTROL, &tmp);
	tmp &= ~3;
	pci_write_config_dword(oczi->pdev, PCR_LINK_CONTROL, tmp);

	oczpcie_show_pcie_usage(oczi);

	/* Init Chip */
	/* make sure RST is set; HBA_RST /should/ have done that for us */
	cctl = mr32(OCZPCIE_CTL) & 0xFFFF;
	if (cctl & CCTL_RST)
		cctl &= ~CCTL_RST;
	else
		mw32_f(OCZPCIE_CTL, cctl | CCTL_RST);

	msleep(1000);

	/* disable Multiplexing, enable phy implemented */
	mw32(OCZPCIE_PORTS_IMP, 0xFF);

	if (revision == VANIR_A0_REV) {
		mw32(OCZPCIE_PA_VSR_ADDR, CMD_CMWK_OOB_DET);
		mw32(OCZPCIE_PA_VSR_PORT, 0x00018080);
	}
	mw32(OCZPCIE_PA_VSR_ADDR, VSR_PHY_MODE2);
	if (revision == VANIR_A0_REV || revision == VANIR_B0_REV)
		/* set 6G/3G/1.5G, multiplexing, without SSC */
		mw32(OCZPCIE_PA_VSR_PORT, 0x0084d4fe);
	else
		/* set 6G/3G/1.5G, multiplexing, with and without SSC */
		mw32(OCZPCIE_PA_VSR_PORT, 0x0084fffe);

	if (revision == VANIR_B0_REV) {
		mw32(OCZPCIE_PA_VSR_ADDR, CMD_APP_MEM_CTL);
		mw32(OCZPCIE_PA_VSR_PORT, 0x08001006);
		mw32(OCZPCIE_PA_VSR_ADDR, CMD_HOST_RD_DATA);
		mw32(OCZPCIE_PA_VSR_PORT, 0x0000705f);
	}

	/* reset control */
	mw32(OCZPCIE_PCS, 0);		/* OCZPCIE_PCS */
	mw32(OCZPCIE_STP_REG_SET_0, 0);
	mw32(OCZPCIE_STP_REG_SET_1, 0);

	/* init phys */
	oczpcie_phy_hacks(oczi);

	/* disable non data frame retry */
	tmp = oczpcie_cr32(oczi, CMD_SAS_CTL1);
	if ((revision == VANIR_A0_REV) ||
		(revision == VANIR_B0_REV) ||
		(revision == VANIR_C0_REV)) {
		tmp &= ~0xffff;
		tmp |= 0x007f;
		oczpcie_cw32(oczi, CMD_SAS_CTL1, tmp);
	}

	/* set LED blink when IO*/
	mw32(OCZPCIE_PA_VSR_ADDR, VSR_PHY_ACT_LED);
	tmp = mr32(OCZPCIE_PA_VSR_PORT);
	tmp &= 0xFFFF00FF;
	tmp |= 0x00003300;
	mw32(OCZPCIE_PA_VSR_PORT, tmp);

	mw32(OCZPCIE_CMD_LIST_LO, oczi->slot_dma);
	mw32(OCZPCIE_CMD_LIST_HI, (oczi->slot_dma >> 16) >> 16);

	mw32(OCZPCIE_RX_FIS_LO, oczi->rx_fis_dma);
	mw32(OCZPCIE_RX_FIS_HI, (oczi->rx_fis_dma >> 16) >> 16);

	mw32(OCZPCIE_TX_CFG, OCZPCIE_CHIP_SLOT_SZ);
	mw32(OCZPCIE_TX_LO, oczi->tx_dma);
	mw32(OCZPCIE_TX_HI, (oczi->tx_dma >> 16) >> 16);

	mw32(OCZPCIE_RX_CFG, OCZPCIE_RX_RING_SZ);
	mw32(OCZPCIE_RX_LO, oczi->rx_dma);
	mw32(OCZPCIE_RX_HI, (oczi->rx_dma >> 16) >> 16);

	for (i = 0; i < N_PHY; i++) {
		oczpcie_phy_disable(oczi, i);
		/* set phy local SAS address */
		oczpcie_set_sas_addr(oczi, i, CONFIG_ID_FRAME3, CONFIG_ID_FRAME4,
						cpu_to_le64(oczi->phy[i].dev_sas_addr));

		oczpcie_enable_xmt(oczi, i);
		oczpcie_config_reg_from_hba(oczi, i);
		oczpcie_phy_enable(oczi, i);

		chip_phy_reset(oczi, i, OCZPCIE_PHY_TUNE);
	}
	msleep(500);
	for (i = 0; i < N_PHY; i++) {
		chip_detect_porttype(oczi, i);
	}

	for (i = 0; i < N_PHY; i++) {
		/* clear phy int status */
		tmp = oczpcie_read_port_irq_stat(oczi, i);
		tmp &= ~PHYEV_SIG_FIS;
		oczpcie_write_port_irq_stat(oczi, i, tmp);

		/* set phy int mask */
		tmp = PHYEV_RDY_CH | PHYEV_BROAD_CH |
			PHYEV_ID_DONE  | PHYEV_DCDR_ERR | PHYEV_CRC_ERR ;
		oczpcie_write_port_irq_mask(oczi, i, tmp);

		msleep(100);
		oczpcie_update_phyinfo(oczi, i, 1);
	}

	/* little endian for open address and command table, etc. */
	cctl = mr32(OCZPCIE_CTL);
	cctl |= CCTL_ENDIAN_CMD;
	cctl &= ~CCTL_ENDIAN_OPEN;
	cctl |= CCTL_ENDIAN_RSP;
	mw32_f(OCZPCIE_CTL, cctl);

	/* reset CMD queue */
	tmp = mr32(OCZPCIE_PCS);
	tmp |= PCS_CMD_RST;
	tmp = ~PCS_SELF_CLEAR;
	mw32(OCZPCIE_PCS, tmp);
	/*
	 * the max count is 0x1ff, while our max slot is 0x200,
	 * it will make count 0.
	 */
	tmp = 0;
	if (OCZPCIE_CHIP_SLOT_SZ > 0x1ff)
		mw32(OCZPCIE_INT_COAL, 0x1ff | COAL_EN);
	else
		mw32(OCZPCIE_INT_COAL, OCZPCIE_CHIP_SLOT_SZ | COAL_EN);

	/* default interrupt coalescing time is 128us */
	tmp = 0x10000 | oczi->interrupt_coalescing;
	mw32(OCZPCIE_INT_COAL_TMOUT, tmp);

	/* ladies and gentlemen, start your engines */
	mw32(OCZPCIE_TX_CFG, 0);
	mw32(OCZPCIE_TX_CFG, OCZPCIE_CHIP_SLOT_SZ | TX_EN);
	mw32(OCZPCIE_RX_CFG, OCZPCIE_RX_RING_SZ | RX_EN);
	/* enable CMD/CMPL_Q/RESP mode */
	mw32(OCZPCIE_PCS, PCS_SATA_RETRY_2 | PCS_FIS_RX_EN |
		PCS_CMD_EN | PCS_CMD_STOP_ERR);

	/* enable completion queue interrupt */
	tmp = (CINT_PORT_MASK | CINT_DONE | CINT_MEM |
		CINT_DMA_PCIE | CINT_NON_SPEC_NCQ_ERROR);
	tmp |= CINT_PHY_MASK;
	mw32(OCZPCIE_INT_MASK, tmp);

	tmp = oczpcie_cr32(oczi, CMD_LINK_TIMER);
	tmp |= 0xFFFF0000;
	oczpcie_cw32(oczi, CMD_LINK_TIMER, tmp);

	/* tune STP performance */
	tmp = 0x003F003F;
	oczpcie_cw32(oczi, CMD_PL_TIMER, tmp);

	/* This can improve expander large block size seq write performance */
	tmp = oczpcie_cr32(oczi, CMD_PORT_LAYER_TIMER1);
	tmp |= 0xFFFF007F;
	oczpcie_cw32(oczi, CMD_PORT_LAYER_TIMER1, tmp);

	/* change the connection open-close behavior (bit 9)
	 * set bit8 to 1 for performance tuning */
	tmp = oczpcie_cr32(oczi, CMD_SL_MODE0);
	tmp |= 0x0000200;
	/* set bit0 to 0 to enable retry for no_dest reject case */
//	tmp &= 0xFFFFFFFE;
	oczpcie_cw32(oczi, CMD_SL_MODE0, tmp);

	/* Enable SRS interrupt */
	mw32(OCZPCIE_INT_MASK_SRS_0, 0xFFFF);

	// some system BIOSs change the read size, which casues DMA issues
	// set the correct value
	pci_read_config_dword(oczi->pdev, PCR_DEV_CTRL, &tmp);
	if ((tmp & OCZ_PCI_RD_REQ_MASK) > OCZ_PCI_RD_REQ_SIZE) {
		tmp &= ~OCZ_PCI_RD_REQ_MASK;
		tmp |= OCZ_PCI_RD_REQ_SIZE;
		pci_write_config_dword(oczi->pdev, PCR_DEV_CTRL, tmp);
	}

	oczi->n_phy = oczi->phys_ready;
	return 0;
}

int chip_ioremap(struct oczpcie_info *oczi)
{
	if (!oczpcie_ioremap(oczi, 2, -1)) {
		oczi->regs_ex = oczi->regs + 0x10200;
		oczi->regs += 0x20000;
		if (oczi->id == 1)
			oczi->regs += 0x4000;
		return 0;
	}
	return -1;
}

void chip_iounmap(struct oczpcie_info *oczi)
{
	if (oczi->regs) {
		oczi->regs -= 0x20000;
		if (oczi->id == 1)
			oczi->regs -= 0x4000;
		oczpcie_iounmap(oczi->regs);
	}
}

void chip_interrupt_enable(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs_ex;

	mw32(OCZPCIE_GPL_INT_ENABLE, (IRQ_SAS_A | IRQ_SAS_B));
	return;
}

void chip_interrupt_disable(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs_ex;

	mw32(OCZPCIE_GPL_INT_ENABLE, 0);
	return;
}

u32 chip_isr_status(struct oczpcie_info *oczi, int irq)
{
	void __iomem *regs = oczi->regs_ex;
	u32 stat = 0;
	stat = mr32(OCZPCIE_GBL_INT_STAT);

	if (!(stat & (IRQ_SAS_A | IRQ_SAS_B)))
		return 0;

	return stat;
}

irqreturn_t chip_isr(struct oczpcie_info *oczi, int irq, u32 stat)
{
	void __iomem *regs = oczi->regs;
	unsigned long flags = 0;

	if (((stat & IRQ_SAS_A) && oczi->id == 0) ||
			((stat & IRQ_SAS_B) && oczi->id == 1)) {
		mw32_f(OCZPCIE_INT_STAT, CINT_DONE);

		if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_lock_bh(&oczi->lock);
		else
			spin_lock_irqsave(&oczi->lock, flags);

		oczpcie_int_full(oczi);

		if (likely(oczi->prv_info->oczi[0]->flags & MVF_FLAG_THREADED_IRQ))
			spin_unlock_bh(&oczi->lock);
		else
			spin_unlock_irqrestore(&oczi->lock, flags);
	}
	return IRQ_HANDLED;
}

void chip_wait_for_active(struct oczpcie_info *oczi, u32 slot_idx)
{
	u32 tmp;
	u32 register_offset;
	int cnt = 0;

	register_offset = ((slot_idx >> 5) << 2);	// 32-bits per register
	tmp = oczpcie_cr32(oczi, OCZPCIE_COMMAND_ACTIVE+register_offset);
	while (tmp & 1 << (slot_idx % 32)) {
		udelay(10);
		tmp = oczpcie_cr32(oczi, OCZPCIE_COMMAND_ACTIVE+register_offset);
		if (cnt++ > 100) {
			break;
		}
	}
	if (cnt > 0) {
		mdelay(10);
	}
}

void chip_command_active(struct oczpcie_info *oczi, u32 slot_idx)
{
	u32 tmp;
	u32 register_offset;

	register_offset = ((slot_idx >> 5) << 2);	// 32-bits per register
	tmp = oczpcie_cr32(oczi, OCZPCIE_COMMAND_ACTIVE+register_offset);
	if (tmp & 1 << (slot_idx % 32)) {
		oczpcie_dprintk("command active %08X,  slot [%x].\n", tmp, slot_idx);
		oczpcie_cw32(oczi, OCZPCIE_COMMAND_ACTIVE + register_offset,
			1 << (slot_idx % 32));
		chip_wait_for_active(oczi, slot_idx);
	}
}

void chip_clear_srs_irq(struct oczpcie_info *oczi, u8 reg_set, u8 clear_all)
{
	void __iomem *regs = oczi->regs;
	u32 tmp;

	if (clear_all) {
		tmp = mr32(OCZPCIE_INT_STAT_SRS_0);
		if (tmp) {
			oczpcie_dprintk("check SRS 0 %08X.\n", tmp);
			mw32(OCZPCIE_INT_STAT_SRS_0, tmp);
		}
		tmp = mr32(OCZPCIE_INT_STAT_SRS_1);
		if (tmp) {
			oczpcie_dprintk("check SRS 1 %08X.\n", tmp);
			mw32(OCZPCIE_INT_STAT_SRS_1, tmp);
		}
	} else {
		if (reg_set > 31)
			tmp = mr32(OCZPCIE_INT_STAT_SRS_1);
		else
			tmp = mr32(OCZPCIE_INT_STAT_SRS_0);

		if (tmp & (1 << (reg_set % 32))) {
			oczpcie_dprintk("register set 0x%x was stopped.\n", reg_set);
			if (reg_set > 31)
				mw32(OCZPCIE_INT_STAT_SRS_1, 1 << (reg_set % 32));
			else
				mw32(OCZPCIE_INT_STAT_SRS_0, 1 << (reg_set % 32));
		}
	}
}

void chip_issue_stop(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs;
	u32 tmp;

	chip_clear_srs_irq(oczi, 0, 1);

	tmp = mr32(OCZPCIE_INT_STAT);
	mw32(OCZPCIE_INT_STAT, tmp | CINT_CI_STOP);
	tmp = mr32(OCZPCIE_PCS) | 0xFF00;
	mw32(OCZPCIE_PCS, tmp);
}

void chip_non_spec_ncq_error(struct oczpcie_info *oczi)
{
	void __iomem *regs = oczi->regs;
	u32 err_0, err_1;
	int reg, tag;
	int was_okay;
	int dev = -1;

	err_0 = mr32(OCZPCIE_NON_NCQ_ERR_0);
	err_1 = mr32(OCZPCIE_NON_NCQ_ERR_1);

	oczpcie_dprintk("non specific ncq error err_0:%x,err_1:%x.\n",
			err_0, err_1);
	if (unlikely(err_1))
		printk("Unexpected err_1 %x\n", err_1);

	mdelay(1);

	for (reg = 0; reg < 32; reg++) {
		if (err_0 & bit(reg)) {
			u8 reg_set = reg;
			int phy;

			for (phy = 0; phy < N_PHY; phy++) {
				if (oczi->phymap[phy] == reg) {
					dev = phy;
				}
			}
			if (dev == -1) {
				dev_printk(KERN_ERR, oczi->dev, "Unable find device for PHY %d\n", reg);
				return;
			}

			dev_printk(KERN_ERR, oczi->dev, "Non specific NCQ error on controller %d, device %d, PHY %d\n", oczi->id, dev, reg);
			mdelay(100);
			was_okay = (oczi->devices[reg].dev_status == OCZPCIE_DEV_NORMAL);
			oczi->devices[reg].dev_status = OCZPCIE_DEV_EH;
			for (tag = 0; tag < MAX_NCQ_DEPTH; tag++) {
				int slot_idx;

				slot_idx = calc_slot(dev, tag);
				if (oczi->slot_info[slot_idx].task) {
					*(u32 *)oczi->slot_info[slot_idx].response = cpu_to_le32(TFILE_ERR);
					oczpcie_slot_complete(oczi, slot_idx | RXQ_ERR | RXQ_SLOT_RESET);
					chip_command_active(oczi, slot_idx);
					oczpcie_int_rx(oczi, 0);
				}
			}
			mdelay(100);
			chip_free_reg_set(oczi, &reg_set);
			chip_assign_specified_reg_set(oczi, reg);

			if (was_okay) {
				oczpcie_diag_handle_ncq_error(oczi, &oczi->devices[reg]);
			}
		}
	}

	mw32(OCZPCIE_NON_NCQ_ERR_0, err_0);
	mw32(OCZPCIE_NON_NCQ_ERR_1, err_1);
}

void chip_free_reg_set(struct oczpcie_info *oczi, u8 *tfs)
{
	void __iomem *regs = oczi->regs;
	u8 reg_set = *tfs;

	if (*tfs == OCZPCIE_ID_NOT_MAPPED)
		return;

	oczi->sata_reg_set &= ~bit(reg_set);
	if (reg_set < 32)
		w_reg_set_enable(reg_set, (u32)oczi->sata_reg_set);
	else
		w_reg_set_enable(reg_set, (u32)(oczi->sata_reg_set >> 32));

	*tfs = OCZPCIE_ID_NOT_MAPPED;

	return;
}

void chip_assign_specified_reg_set(struct oczpcie_info *oczi, u8 set)
{
	void __iomem *regs = oczi->regs;

	if (set >= 32) {
		oczi->sata_reg_set |= bit(set);
		w_reg_set_enable(set, (u32)(oczi->sata_reg_set >> 32));
	} else {
		oczi->sata_reg_set |= bit(set);
		w_reg_set_enable(set, (u32)oczi->sata_reg_set);
	}
}

void chip_make_prd(struct scatterlist *scatter, int nr, void *prd)
{
	int i;
	struct scatterlist *sg;
	struct oczpcie_prd *buf_prd = prd;
	struct oczpcie_prd_imt im_len;
	*(u32 *)&im_len = 0;
	for_each_sg(scatter, sg, nr, i) {
		buf_prd->addr = cpu_to_le64(sg_dma_address(sg));
		im_len.len = sg_dma_len(sg);
		buf_prd->im_len = cpu_to_le32(*(u32 *)&im_len);
		buf_prd++;
	}
}

int chip_oob_done(struct oczpcie_info *oczi, int i)
{
	u32 phy_st;
	phy_st = oczpcie_read_phy_ctl(oczi, i);
	if (phy_st & PHY_READY_MASK)
		return 1;
	return 0;
}

void chip_fix_phy_info(struct oczpcie_info *oczi, int i)
{
	struct oczpcie_phy *phy = &oczi->phy[i];
	oczpcie_dprintk("get all reg link rate is 0x%x\n", phy->phy_status);
	phy->minimum_linkrate = LINK_RATE_1_5_GBPS;
	phy->maximum_linkrate = LINK_RATE_6_0_GBPS;

	if (phy->phy_type & PORT_TYPE_SAS) {
		BUG_ON(1);
	} else {
		phy->att_dev_info = PORT_DEV_STP_TRGT | 1;
	}

	/* enable spin up bit */
	oczpcie_write_port_cfg_addr(oczi, i, PHYR_PHY_STAT);
	oczpcie_write_port_cfg_data(oczi, i, 0x04);

}

void chip_clear_active_cmds(struct oczpcie_info *oczi)
{
	u32 tmp;
	void __iomem *regs = oczi->regs;
	tmp = mr32(OCZPCIE_STP_REG_SET_0);
	mw32(OCZPCIE_STP_REG_SET_0, 0);
	mw32(OCZPCIE_STP_REG_SET_0, tmp);
	tmp = mr32(OCZPCIE_STP_REG_SET_1);
	mw32(OCZPCIE_STP_REG_SET_1, 0);
	mw32(OCZPCIE_STP_REG_SET_1, tmp);
}
