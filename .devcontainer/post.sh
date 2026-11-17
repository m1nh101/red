#!/bin/bash

apt-get update
apt install -y python3 gdb file checksec netcat-openbsd nasm libcapstone-dev
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
chsh -s /usr/bin/zsh vscode