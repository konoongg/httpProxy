ulimit -c unlimited
clear 
make clean
make
./httpProxy --help
./httpProxy -t 4 --port 8080 
