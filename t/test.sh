clear
mkdir results

curl -o results/result-0 --http1.0 --progress-bar  --proxy1.0 localhost:8080  http://kremlin.ru/
curl -o results/result-1 --http1.0 --progress-bar  --proxy1.0 localhost:8080  http://xcal1.vodafone.co.uk/
curl -o results/result-2 --http1.0 --progress-bar  --proxy1.0 localhost:8080  http://gramota.ru/
curl -o results/result-3 --http0.9 --http1.0 --progress-bar  --proxy1.0 localhost:8080 http://xcal1.vodafone.co.uk/20MB.zip

cd os-proxy-tests
./1-sequential.sh
./2-concurrent-batches.sh