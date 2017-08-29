rm -rf output
mkdir output
gcc -shared -fPIC network_hook.c -o output/koala-libc.so -ldl
echo "compiled to output/koala-libc.so"