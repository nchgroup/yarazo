#!/bin/bash


if [ ! -d "yara-rules" ]; then
    mkdir yara-rules
else 
    rm -rf yara-rules
    mkdir yara-rules
fi

git clone https://github.com/roadwy/DefenderYara.git yara-rules/DefenderYara
git clone https://github.com/elastic/protections-artifacts.git yara-rules/protections-artifacts
