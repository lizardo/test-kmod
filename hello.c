#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

static int __init hello_init(void)
{
	void *p1 = kmalloc(100, 0);
	void *p2 = kmalloc(4096 * 2 + 1, 0);
	void *p3 = kmalloc(100, 1);
	printk("Hello, world! p1 = %p, p2 = %p, p3 = %p\n", p1, p2, p3);
	kfree(p1);
	kfree(p2);
	kfree(p3);

	return 0;
}

static void __exit hello_exit(void)
{
	printk("Good bye, world!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hello module");
