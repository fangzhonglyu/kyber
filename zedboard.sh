#!/bin/bash

cd ../
zip -y -r kyber.zip kyber
scp kyber.zip $(whoami)@zhang-zedboard-06.ece.cornell.edu:~
rm kyber.zip
ssh $(whoami)@zhang-zedboard-06.ece.cornell.edu -t 'rm -rf ~/kyber; unzip kyber.zip; cd kyber/zedboard; bash -l'