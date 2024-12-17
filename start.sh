ulimit -c unlimited
clear 
make clean
make
./httpProxy_with_san --help
./httpProxy_with_san -t 4 --port 8080 
