#!/bin/bash

if [ ! -d "yara-rules" ]; then
    echo "The 'yara-rules/' folder does not exist"
else
    cd yara-rules
    cd DefenderYara && git pull && cd ..
    cd protections-artifacts && git pull && cd ..
    cd ..
fi
