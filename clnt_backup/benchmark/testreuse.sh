#!/usr/bin/env bash

TARGET_ADDRESS=172.31.36.248
BATCH_SIZE=1000
REUSE_SESSION=1
REUSE_MAX=10

DATA_FILE=64K.bin

OUTPUT_DIR=$(pwd)/out

if [ ! -d "$OUTPUT_DIR" ]; then
  mkdir -p $OUTPUT_DIR
fi

cd $OUTPUT_DIR

rm -f *.out

echo reusing $REUSE_MAX

COUNTER=$REUSE_SESSION
let SESSION="$BATCH_SIZE"/"$REUSE_SESSION"
while [  $COUNTER -le $REUSE_MAX ]; do
  echo  
  echo Testing "$COUNTER"
  httperf --hog --server=$TARGET_ADDRESS --port=443 --ssl --wsess=$SESSION,$COUNTER,0 --burst-len=$COUNTER --ssl-ciphers=AES256-GCM-SHA384 --uri=/"DATA_FILE" | tee "$COUNTER"_RSA.out
  httperf --hog --server=$TARGET_ADDRESS --port=443 --ssl --wsess=$SESSION,$COUNTER,0 --burst-len=$COUNTER  --ssl-ciphers=ECDHE-RSA-AES256-GCM-SHA384 --uri=/"DATA_FILE"  | tee "$COUNTER"_ECDHE.out
  let COUNTER=COUNTER+1
done
