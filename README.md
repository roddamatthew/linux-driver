## Useful commands!

- Instantiate the module with:
	- `sudo insmod <name>.ko`
- Remove the module with:
	- `sudo rmmod <name>`
- View module info with:
	- `modinfo <name>`
- View all modules with:
	- `lsmod`
- View the kernel FD with:
	- `sudo dmesg`
	- `-W` to filter for only new messages
- Create a device:
	- `sudo mknod /dev/<device_name> c <major_device_num> <minor_device_num>`

## Device Basics

- There are two types of devices in Linux:
	- Character devices
		- Its like a stream or TCP
	- Block devices
		- Its like an array or UDP
- Devices all have a major and minor device number
	- Major device numbers typically identify the type of device
	- Minor device numbers typically identify instantiations of one type of device
		- e.g. Different tty may have minor device number 1, 2, 3, etc.
- The list of currently loaded devices is in `/proc/dev`
- Devices are linked to device drivers by their major and minor device numbers
- We can create new device files with `mknod`:
	- Have to specify a name, major/minor ID and type ('c' or 'b')
- Devices to drivers is a many to one relationship:
	- I can instantiate many devices (with the same major but different minor dev nums)
	- All devices will share the same driver that allocated their major dev num

