#!/bin/bash

scp xillydemo.bit $(whoami)@zhang-zedboard-$1.ece.cornell.edu:~
ssh $(whoami)@zhang-zedboard-$1.ece.cornell.edu -t 'mount /mnt/sd; cp xillydemo.bit /mnt/sd; sudo reboot'