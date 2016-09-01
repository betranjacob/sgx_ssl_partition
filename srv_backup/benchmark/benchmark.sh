#!/usr/bin/env bash

TARGET_ADDRESS=172.31.36.248
BATCH_SIZE=5000
REUSE_SESSION=1

SIZE_MIN=1
SIZE_MAX=32768
SIZE_INC=2
SIZE_SUFFIX=K

OUTPUT_DIR=$(pwd)/out

if [ ! -d "$OUTPUT_DIR" ]; then
  mkdir -p $OUTPUT_DIR
fi

cd $OUTPUT_DIR

rm -f *.out

COUNTER=$SIZE_MIN
let SESSION=BATCH_SIZE/REUSE_SESSION
while [  $COUNTER -le $SIZE_MAX ]; do
  echo  
  echo Benchmarking "$COUNTER""$SIZE_SUFFIX"
  httperf --hog --server=$TARGET_ADDRESS --port=443 --ssl --wsess=$SESSION,$REUSE_SESSION,0 --burst-len=$REUSE_SESSION --ssl-ciphers=AES256-GCM-SHA384 --uri=/"$COUNTER""$SIZE_SUFFIX".bin | tee "$COUNTER""$SIZE_SUFFIX"_RSA.out
  httperf --hog --server=$TARGET_ADDRESS --port=443 --ssl --wsess=$SESSION,$REUSE_SESSION,0 --burst-len=$REUSE_SESSION --ssl-ciphers=ECDHE-RSA-AES256-GCM-SHA384 --uri=/"$COUNTER""$SIZE_SUFFIX".bin | tee "$COUNTER""$SIZE_SUFFIX"_ECDHE.out
  let COUNTER=COUNTER*SIZE_INC
done
