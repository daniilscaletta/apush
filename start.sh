#!/bin/bash
source myenv/bin/activate
sleep 1

DEFAULT_HOST="bourd.vkactf.ru"

if [ -z "$1" ]; then
  HOST="$DEFAULT_HOST"
elif [ -z "$2" ]; then
  HOST="$1"
else
  HOST="$1:$2"
fi

python3 script.py "$HOST"