# Linux Firewall

Implementation of a simple Linux Firewall using Netfilter for packet manipulation. The source code is licensed under MIT license (see [LICENSE]) and you should use it (insert builded kernel module) ONLY at your OWN RISK.

### User space application
Command line application that communicates with a given kernel module. The possible command line arguments are following:

* argument `-a RULE`
 * add specific rule to the filtering logic 
 * `RULE`: `NUMBER ACTION PROTOCOL FROM address TO address src dst`, where `address` is `IP` or `ANY`, `src` is optional (`SRCPORT NUMBER`) and `dst` is optional destination port (`DSTPORT NUMBER`). 
* argument `-f FILTER-FILE`
 * add all rules defined in the file `FILTER-FILE` to the filtering logic
* argument `-d RULE-ID`
 * delete rule from the filtering logic
 * `RULE-ID` is a rule identificator
* argument `-p`
 * print list of rules defined in the module


### Kernel module
Implementation of the kernel modul for Linux in version compatible with kernel version 3.13.


### Provided files
The repository contains files

* `pdsfw.c` - kernel module
* `pdscli.c` - user space application
* `lexer.l` - lexical analyzer ([flex]) input
* `parser.y` - parser ([bison]) input
* `Makefile`

Using the `make` command it is possible to build user space application and kernel module. The kernel module can be loaded using command `insmod pdsfw.ko` (at your own risk !!!) and removed using command `rmmod pdsfw`. In case of unexpected problems (eg. failure due to lack of memory, ...), the state is written in log file which can be displayed using command `dmesg`.

### References
* [How to Write a Linux Firewall]
* [Course: Data Communications, Computer Networks and Protocols]

[How to Write a Linux Firewall]: http://www.roman10.net/a-linux-firewall-using-netfilter-part-1overview/
[Course: Data Communications, Computer Networks and Protocols]: http://www.fit.vutbr.cz/study/course-l.php.en?id=11584
[flex]: http://flex.sourceforge.net/
[bison]: https://www.gnu.org/software/bison/
[LICENSE]: https://github.com/JakubVojvoda/linux-firewall/blob/master/LICENSE