#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/pam-voice-authentication.c
sudo ld -x --shared -o /lib/security/pam-voice-authentication.so -lasound pam-voice-authentication.o
rm pam-voice-authentication.o
