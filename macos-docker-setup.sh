#!/bin/bash
if ! [ -x "$(command -v docker)" ]; then
    echo "Docker must be installed prior to setup, exiting"
    exit
fi

CONTAINERID=$(docker run --rm -it -d -v $(pwd):/app -p 8080:8080 mitmproxy/mitmproxy:7.0.4 /bin/bash)
echo "Container created with ID $CONTAINERID"

# start and quit mitmproxy to generate certificates
echo "Starting and quitting mitmproxy to generate certificates"
docker exec -it $CONTAINERID bash -c 'mitmdump & mitmproxy_pid=$!; sleep 2s; kill -KILL $mitmproxy_pid'

# pull mitmproxy ca from container and trust on host
echo 'Pulling mitmproxy CA cert from the container'
echo 'You will need to trust this on the host'
docker cp $CONTAINERID:/root/.mitmproxy/mitmproxy-ca-cert.pem .

# installing requirements
echo 'Installing Requirements for mitmproxy extension'
docker exec -it $CONTAINERID /app/install-requirements-ubuntu.sh

# starting mitmproxy
echo 'Starting mitmproxy in container with "mitmproxy -s /app/wallet_connect_decryptor.py"'
docker exec -it	$CONTAINERID mitmproxy -s /app/wallet_connect_decryptor.py



