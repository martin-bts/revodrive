/*
 * ioctl.c
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

#include	<linux/types.h>
#include	<linux/blkdev.h>
#include	<linux/ioctl.h>
#include	<linux/hdreg.h>
#include	"oczpcie_main.h"
#include	"oczpcie_iface.h"
#include	"sg_io.h"

int oczpcie_ioctl(struct block_device *dev, fmode_t mode, unsigned cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd)
	{
		case HDIO_GETGEO:
		{
			struct hd_geometry geo;

			oczpcie_getgeo(dev, &geo);
			if (unlikely(copy_to_user((void __user *)arg, &geo, sizeof(geo))))
				ret = -EFAULT;
			break;
		}

		case SG_IO:
			ret = oczpcie_sg_io(dev, cmd, arg);
			break;

		default:
			oczpcie_dprintk("Received unknown ioctl %x\n", cmd);
			ret = -ENOTTY;
			break;
	}
	return ret;
}



