#!/bin/bash

scp xillydemo.bit $(uname)@zhang-zedboard-06.ece.cornell.edu:~
ssh $(uname)@zhang-zedboard-06.ece.cornell.edu -t 'mount /mnt/sd; cp xillydemo.bit /mnt/sd; sudo reboot'