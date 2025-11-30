#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>

// Create a custom read function for our new device
static ssize_t my_read(struct file *f, char __user *u, size_t l, loff_t *o) {
	printk("[hello] - Read is called!!!\n");
	return 0;
}

static int major_device_num ; // Device number
static char device_name[] = "my_cdevice";
static struct file_operations fops = {
	.read = my_read
};

static int __init my_init(void) {
	major_device_num = register_chrdev(0, device_name, &fops);
	if (major_device_num < 0) {
		printk("[hello] error registering device!");
		return -1;		
	}

	printk("[hello] registered '%s' with major device num: %d!\n", device_name, major_device_num); 
	return 0;	
}

static void __exit my_exit(void) {
	unregister_chrdev(major_device_num, device_name);
	printk("[hello] Goodbye Kernel!\n");
	 
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("roddamatthew");
MODULE_DESCRIPTION("A minimal driver for learning!");
