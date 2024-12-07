#!/bin/bash

sudo apt-get install -y python-setuptools

cd pox_module
sudo python2 setup.py develop

pkill -9 sr_solution
pkill -9 sr

