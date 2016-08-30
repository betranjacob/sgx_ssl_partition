#!/usr/bin/env bash

# this script searches source files for function names from the function list
# and copies the source to an output file

function_list=results/function_list
output_prefix=tcb_sources
output_prefix_NF=tcb_sources_NF	# not found
output_prefix_MF=tcb_sources_MF # multiple files
output_prefix_LIBC=tcb_sources_LIBC # libc functions


search_folders="./build/libressl-2.4.1/ssl ./build/libressl-2.4.1/crypto ./build/opensgx/user/test/openssl ./build/nginx-1.11.1/src"

declare -a arr=("stock" "outside" "inside")

## now loop through the above array
for TEST_SUFFIX in "${arr[@]}"
do
	FUNCTION_LIST=${function_list}_${TEST_SUFFIX}.txt

	if [ ! -f $FUNCTION_LIST ]; then
		echo "${FUNCTION_LIST} does not exist."
		continue
	fi

	output=results/${output_prefix}_${TEST_SUFFIX}.c
	not_found=results/${output_prefix_NF}_${TEST_SUFFIX}.txt
	multiple_files=results/${output_prefix_MF}_${TEST_SUFFIX}.txt
	libc_functions=results/${output_prefix_LIBC}_${TEST_SUFFIX}.txt

	> "$output"
	> "$not_found"
	> "$multiple_files"
	> "$libc_functions"

	while read NAME
	do
	  # echo "$NAME"
	  file=$(grep -rl --include \*.c "^$NAME(" ${search_folders})
	  # echo "$file"

	  if [[ $(grep -c . <<< "$file") > 1 ]];
	  then
	    echo "$NAME found in multiple files."
	    echo "$NAME" >> "$multiple_files"
	  else
	    if [[ -z "${file// }" ]];
	    then
         
	      if [[ $(grep -c $NAME /lib/x86_64-linux-gnu/libc.so.6) > 0 ]];
	      then
	        echo "$NAME is a libc function"
	        echo "$NAME" >> "$libc_functions"
	      else  	
	        echo "$NAME not found"
	        echo "$NAME" >> "$not_found"
	      fi
	    else
	      # echo "$NAME found in $file"
	      preamble=$(grep -h -r --include \*.c "^$NAME(" ${search_folders} -B1 | head -n 1)
	      result=$(sed -n "/^$NAME/,/^}/p" "$file")
	      
	      echo "$preamble" >> "$output"
	      echo "$result" >> "$output"
	      printf "\n\n" >> "$output"
	      # printf "${preamble}\n${result}\n\n" >> "$output"
	    fi	
	  fi
	done < $FUNCTION_LIST
done

for TEST_SUFFIX in "${arr[@]}"
do
	TCB=results/${output_prefix}_${TEST_SUFFIX}.c
	echo "$TEST_SUFFIX"
	cloc $TCB
done
