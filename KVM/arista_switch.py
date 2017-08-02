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

source_device = '<source_device>';
vm_name = '<vm_name>';
cpu = '<cpu>';
ram = '<ram>';

iso_image_name='Aboot-veos-2.0.8.iso';
qcow2_image_name='Arista.qcow2';

source_folder = '/home/Original_Image/';
destination_folder_qcow2='/'+vm_name+'_qcow2/';
destination_folder_iso='/'+vm_name+'_iso/';

AVX::CMD(source_device+':@'+'mkdir '+destination_folder_qcow2);
AVX::CMD(source_device+':@'+'mkdir '+destination_folder_iso);
AVX::CMD(source_device+':@'+'cp '+source_folder+iso_image_name+' '+destination_folder_iso);
AVX::CMD(source_device+':@'+'cp '+source_folder+qcow2_image_name+' '+destination_folder_qcow2);
AVX::CMD(source_device+':@'+ 'virt-install -n '+vm_name+' --ram='+ram+' --vcpus='+cpu+' --graphics=vnc --cdrom='+destination_folder_iso+iso_image_name+' --disk path='+destination_folder_qcow2+qcow2_image_name+',format=qcow2 --boot cdrom,hd=on  --force --network bridge=br0,model=e1000 --network bridge=br1,model=e1000 --network bridge=br2,model=e1000');


path = os.path.dirname(os.getcwd())
client = appviewx.db_connection()
device_list = client.appviewx.device
    
def decyrpt(EncryptedPassword, Key):
   decrypt_jar_path = path + '/properties/DecryptAPS.jar'
   java_path = path + '/jre/bin/java'
   cmd = java_path + ' -Dappviewx.property.path=/home/appviewx/AppViewX/properties/ -jar ' + decrypt_jar_path + ' ' + EncryptedPassword + ' ' + Key
   # run cli cmd to decrypt jar
   status, output = commands.getstatusoutput(cmd)
   password = ((output.strip('\n')).split(':')[0]).strip()
   return password

def get_device_details(device_name):
    value = device_list.find_one({'name': device_name})
    username = value['access'][0]['userName']
    encPassword = value['access'][0]['password']
    key = value['access'][0]['key']
    ip = value['ip']
    password = decyrpt(encPassword, key)
    return username,password,ip
    
vm_name = '<vm_name>';
source_device = '<source_device>';
username, password, source_ip = get_device_details(source_device)
logs='/home/appviewx/logs/'+vm_name+'/';


#python_path = os.path.join(os.path.dirname(os.getcwd()), 'Python/bin/python',)
file_path = os.path.join(os.path.dirname(os.getcwd()), 'aps/helper/')
python_path='python'

AVX::CMD("N/A:@ " +'mkdir -p '+logs);
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'veos_config.py '+vm_name+' '+username+' '+password+' '+source_ip)
