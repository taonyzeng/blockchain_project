geth --networkid 1337 --mine --miner.threads 1 --datadir "." --nodiscover --http --http.port "8545" --http.corsdomain "*" --http.api eth,web3,personal,net --unlock 0 --password ./password.sec --allow-insecure-unlock