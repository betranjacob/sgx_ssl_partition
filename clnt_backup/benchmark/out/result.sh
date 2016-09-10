for file in $( ls *.out -1v ); do
  cat "$file" | grep -E 'SSL/TLS Protocol:|Document Length:|Requests per second:'    
  echo
done

