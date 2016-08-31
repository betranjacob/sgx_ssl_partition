#!/usr/bin/env bash

# process callgrind file to produce function list
# ignores all functions starting with _, 0 or /
# ifnores functions containing ., ?, ' and )

CALLGRIND_PREFIX=callgrind.out
declare -a arr=("stock" "outside" "inside")

now=$(date +"%s")

cd results

## now loop through the above array
for TEST_SUFFIX in "${arr[@]}"
do
  CALLGRIND_FILE=$CALLGRIND_PREFIX.$TEST_SUFFIX

  # make sure callgrind file exists
  if [ ! -f $CALLGRIND_FILE ]; then
  	echo "${CALLGRIND_FILE} does not exist."
    continue
  fi

# uncomment to add time of geration, useful if you dont want to overide results
# cat $CALLGRIND_FILE | grep "cob\|cfl\|cfn\|fn" | grep " " | grep -o "[^ ]*$" | grep "^[^_0/]" | grep -v "[.?\']" | sort -u > function_list_${TEST_SUFFIX}_${now}.txt
cat $CALLGRIND_FILE | grep "cob\|cfl\|cfn\|fn" | grep " " | grep -o "[^ ]*$" | grep "^[^_0/]" | grep -v "[.?\')]" | sort -u > function_list_${TEST_SUFFIX}.txt
done

cd ..
