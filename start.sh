ulimit -c unlimited
clear
make clean
make
./httpProxy_with_san --help
./httpProxy_with_san -t 1 --port 8080  -i 2gb -l 0
