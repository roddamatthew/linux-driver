#include <linux/module.h>
#include <linux/init.h>

static int __init my_init(void) {
	pr_warn("[hello] Hello Kernel!\n"); 
	pr_err("[hello] Hello Kernel!\n"); 
	return 0;	
}

static void __exit my_exit(void) {
	printk("[hello] Goodbye Kernel!\n"); 
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("roddamatthew");
MODULE_DESCRIPTION("A minimal driver for learning!");
