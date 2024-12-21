clear
mkdir results

curl -o results/m_result-0 --http1.0 --progress-bar  --proxy1.0 localhost:8080  http://kremlin.ru/
sleep 5
curl -o results/m_result-2 --http1.0 --progress-bar  --proxy1.0 localhost:8080  http://weather.nsu.ru/ 

