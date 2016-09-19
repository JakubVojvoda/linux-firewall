# Linux Firewall


### User space application

### Kernel module



### Provided files
The repository contains files

* `pdsfw.c` - kernel module
* `pdscli.c` - user space application
* `lexer.l` - lexical analyzer ([flex]) input
* `parser.y` - parser ([bison]) input
* `Makefile` - build module and user space application

Using the `make` command it is possible to build user space application and kernel module. The kernel module can be loaded using command `insmod pdsfw.ko` (at your own risk !!!) and removed using command `rmmod pdsfw`. In case of unexpected problems (eg. failure due to lack of memory, ...), state is written in log file and can be displayed using command `dmesg`.

### References
* [How to Write a Linux Firewall]
* [Course: Data Communications, Computer Networks and Protocols]

[How to Write a Linux Firewall]: http://www.roman10.net/a-linux-firewall-using-netfilter-part-1overview/
[Course: Data Communications, Computer Networks and Protocols]: http://www.fit.vutbr.cz/study/course-l.php.cs?id=11584
[flex]: http://flex.sourceforge.net/
[bison]: https://www.gnu.org/software/bison/
[LICENSE]: https://github.com/JakubVojvoda/linux-firewall/blob/master/LICENSE