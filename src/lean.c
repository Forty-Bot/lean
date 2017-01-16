#include <linux/module.h>


static int __init lean_init(void)
{
	return 0;
}

static void __exit lean_exit(void)
{
}

module_init(lean_init);
module_exit(lean_exit);

MODULE_AUTHOR("Sean Anderson <seanga2@gmail.com>");
MODULE_DESCRIPTION("LEAN file system driver");
