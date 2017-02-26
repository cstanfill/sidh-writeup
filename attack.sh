#!/bin/sh
set -e
set -u

if [ $# -lt 1 ]; then
    echo "Parameters: server:port [cribbed server public key]"
    exit
fi

PATCHED_OPENSSL=./util/openssl
EXTRACT_BIN=./util/extract
PCAP=./data/accesslog.pcap
PORT=443
SERVER=$1
SERVER_PRIV=${2:-}
TSHARK="tshark -d tcp.port==$PORT,ssl -r $PCAP -X lua_script:./util/ex.lua"

rm -rf tmp
mkdir -p tmp

if [ -z "$SERVER_PRIV" ]; then
    echo "Attempting to derive server private key..."
    SERVER_PRIV=$(./util/attack $PATCHED_OPENSSL $SERVER)
    echo "Success! Now it gets easier."
else
    echo "Using provided server private key."
fi

echo "Scraping client public key from pcap..."
CLIENT_PUB=$($TSHARK -Y "ssl.handshake.type == 16" -X lua_script1:ssl.handshake -T fields -e extract.hex | tr ',' '\n'  | grep ^10 | cut -c13-)

echo "Constructing pre-master key..."
PREMASTER=$($EXTRACT_BIN $CLIENT_PUB $SERVER_PRIV)

echo "Scraping client and server randoms from pcap..."
CRAND=$($TSHARK -Y "ssl.handshake.type == 1" -X lua_script1:ssl.handshake.random_time -X lua_script1:ssl.handshake.random_bytes -T fields -e extract.hex | tr -d ',')
SRAND=$($TSHARK -Y "ssl.handshake.type == 2" -X lua_script1:ssl.handshake.random_time -X lua_script1:ssl.handshake.random_bytes -T fields -e extract.hex | tr -d ',')

echo "Deriving TLS v1.2 master secret..."
MASTER=$(./util/generate_master_key $PREMASTER $CRAND $SRAND)

KEYLOGFILE="tmp/keylogfile"
echo CLIENT_RANDOM $CRAND $MASTER > $KEYLOGFILE

# Everything from here down is automated only for convenience, and may break
echo "Attempting to modify pcap to claim a cipher suite that tshark understands..."
PCAP_MOD="tmp/mod.pcap"
xxd -p $PCAP  | tr -d '\n' | sed s/00e01000/00c03100/ | xxd -p -r > $PCAP_MOD

echo "Running tshark with known master secret..."
LOGFILE="./tmp/ws_ssh.log"
tshark -d tcp.port==$PORT,ssl -r $PCAP_MOD -o "ssl.keylog_file:$KEYLOGFILE" -o "ssl.debug_file:$LOGFILE" > /dev/null

echo "--- Done! Here's all the app data I could find in the ssl debug info from tshark:"
cat $LOGFILE | ./util/find_appdata
