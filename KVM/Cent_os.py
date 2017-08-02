import os
import sys
import commands
import base64
import subprocess
import time
sys.path.insert(0,AVX::DEPENDENCIES)
sys.path.insert(0,AVX::HELPER)
import json
import appviewx
reload(appviewx)

source_ip = '<source_ip>';
vm_name = '<vm_name>';
cpu = '<cpu>';
ram = '<ram>';

image_name='cent1.qcow2';
source_folder = '/home/Original_Image/';
destination_folder='/'+vm_name+'_qcow2/';

AVX::CMD(source_ip+':@'+'mkdir '+destination_folder);
AVX::CMD(source_ip+':@'+'cp '+source_folder+image_name+' '+destination_folder);
AVX::CMD(source_ip+':@'+ 'virt-install --name '+vm_name+' --network bridge=br0 --ram='+ram+' --vcpus='+cpu+' --disk path='+destination_folder+image_name+' --import --nographics --serial=pty --os-type=linux --os-variant rhel7');