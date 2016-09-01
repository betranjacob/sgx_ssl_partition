#!/bin/bash

WWW_DIR=/usr/local/nginx/html

SIZE_MIN=1
SIZE_MAX=32768
SIZE_INC=2
SIZE_SUFFIX=K

cd $WWW_DIR
sudo rm -f *.bin

COUNTER=$SIZE_MIN
while [  $COUNTER -le $SIZE_MAX ]; do
  echo  
  echo Generating "$COUNTER""$SIZE_SUFFIX"
  sudo dd if=/dev/urandom of="$COUNTER""$SIZE_SUFFIX".bin count=1 bs="$COUNTER""$SIZE_SUFFIX"
  let COUNTER=COUNTER*SIZE_INC
done

