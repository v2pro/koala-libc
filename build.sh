rm -rf output
mkdir output
gcc -shared -fPIC hook.c -o output/koala-libc.so -ldl
echo "compiled to output/koala-libc.so"