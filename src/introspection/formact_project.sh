#!/bin/bash

find . -name '*.c' -o -name '*.h' | while read -r file; do
	echo "Formatting $file"
	uncrustify -c uncrustify.conf --replace --no-backup "$file"
done

echo "Formatting complete."
