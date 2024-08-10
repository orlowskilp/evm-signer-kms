#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <pem_file>"
    exit 1
fi

PEM_FILE=$1
LINE_NUM=$(cat ${PEM_FILE} | wc -l)

cat $PEM_FILE | tail -n $(($LINE_NUM)) | head -n $(($LINE_NUM - 1)) | base64 -d