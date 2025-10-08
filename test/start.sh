#!/bin/sh

/usr/local/bin/init-ca-database.sh
/usr/local/bin/start-est-server-tls.sh &
/usr/local/bin/start-est-server-mtls.sh &
/usr/local/bin/start-est-server-pop-tls.sh &

echo "Both servers started. Waiting..."
wait