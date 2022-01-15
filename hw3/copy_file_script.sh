#!/bin/bash
cd ~
sudo rm -rf exec_bird_conf/
mkdir exec_bird_conf
cp -a ~/shared/hw3/bird_conf/* exec_bird_conf/