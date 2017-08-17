# koala-libc

If koala-recorder.so is loaded on php-fpm master process, fork() will break golang.
Use koala-libc.so to load koala-recorder.so in the child process to circumvent this problem. 