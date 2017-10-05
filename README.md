## lean

Based on [LEAN v0.6.1](http://freedos-32.sourceforge.net/lean/index.php). 

Currently supports reading. Write support under development.

Significant reference made to 
[krinkinmu's fs](https://github.com/krinkinmu/aufs), and to the ext2 drivers.

### Contributing

All code in this repository should conform to the
[Linux kernel coding style](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst).
Current areas of improvement include
* Adding an option to populate a newly-created filesystem in mkfs
* Creating an automate-testing framework
* Deleting files
