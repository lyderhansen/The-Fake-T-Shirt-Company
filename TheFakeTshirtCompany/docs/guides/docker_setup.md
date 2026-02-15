# Opprett nettverket først (hvis det ikke allerede finnes)
docker network create --subnet=172.30.0.0/24 labnet

# Opprett navngitte volumer
docker volume create fake-tshrt-etc
docker volume create fake-tshrt-var
docker volume create fake-tshrt-data

# Start containeren
docker run -d \
--platform linux/amd64 \
--network labnet \
--ip 172.30.0.12 \
-p 8002:8000 \
-p 8999:8089 \
-p 9998:9997 \
-p 8998:8088 \
-v fake-tshrt-etc:/opt/splunk/etc \
-v fake-tshrt-var:/opt/splunk/var \
-v fake-tshrt-data:/opt/splunk/var/lib/splunk \
-v "<LOCAL_PATH>":/opt/splunk/etc/apps/TA-FAKE-TSHRT \
-e SPLUNK_PASSWORD='adminadmin' \
-e SPLUNK_START_ARGS='--accept-license --answer-yes' \
-e SPLUNK_GENERAL_TERMS='--accept-sgt-current-at-splunk-com' \
--name FAKE-TSHRT \
splunk/splunk:latest


docker exec -u root FAKE-TSHRT chown -R splunk:splunk /opt/splunk/etc/apps/TA-FAKE-TSHRT
docker exec -u root FAKE-TSHRT chmod -R u+rwX /opt/splunk/etc/apps/TA-FAKE-TSHRT
