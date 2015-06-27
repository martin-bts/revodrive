#OCZ RevoDrive 2x drivers for Linux kernels > 3.2.x

Some backgrounder. OCZ does not provide Linux support for older devices in RevoDrive series. However, drivers for 350 work OK, but the compilation fails out of the box. This is due to some changes in kernel functions. This source tree compiles OK, but does not provide any way to package the binary driver(s). You need to move stuff in place manually until I (or you) make correct packaging recipes for Fedora etc.

Please note: at least in my case, the drive is recognized as 2 separate disks. These are /dev/sde and /dev/sdf in my case. You can check the correct partitions with fdisk:

<pre>
$ sudo fdisk -l
...
Disk /dev/sde: 111.8 GiB, 120034123776 bytes, 234441648 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xc088ebc8

Device     Boot  Start       End   Sectors   Size Id Type
/dev/sde1  *      2048    206847    204800   100M  7 HPFS/NTFS/exFAT
/dev/sde2       206848 468879359 468672512 223.5G  7 HPFS/NTFS/exFAT


Disk /dev/sdf: 111.8 GiB, 120034123776 bytes, 234441648 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xc088ebc8
...
</pre>

In this case, we get devices /dev/sde and /dev/sdf. In order to make a single usable device out of these, we must use mdadm:

<pre>
$ sudo mdadm --build /dev/md0 --raid-devices=2 --level=0 /dev/sde /dev/sdf
</pre>

This gives us /dev/md0 that has the correct drive geometry. Now you can just mount the device using whatever means you want. If you want to know what happens, just look at the command line parameters:

--build means we want to build a md device without metadata (ie. superblocks etc.)

/dev/md0 is the device we want to create

--raid-devices=2 means we have 2 devices

--level=0 tells that we want to build a striped drive

and finally /dev/sde and /dev/sdf are the devices to use for building the md0 array.
