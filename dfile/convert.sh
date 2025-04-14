#!/bin/bash
set -e

if [ $# -eq 0 ]; then
    echo "Usage: docker run -v \$(pwd):/convert image_name file.docx"
    exit 1
fi

for file in "$@"; do
    if [[ "$file" == *.docx ]]; then
        echo "Converting $file to PDF..."
        libreoffice --headless --convert-to pdf "$file" --outdir .
    else
        echo "Skipping $file: not a .docx file"
    fi
done

