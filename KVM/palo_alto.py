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
storage_size = '<storage_size>';
image_name='PA-VM-KVM-7.1.0.qcow2'
source_folder = '/home/Original_Image/';
destination_folder='/'+vm_name+'_qcow2/';

AVX::CMD(source_device+':@'+'mkdir '+destination_folder);
AVX::CMD(source_device+':@'+'cp '+source_folder+image_name+' '+destination_folder+' && virt-install --connect qemu:///system --name='+vm_name+' --graphics=vnc --disk path='+destination_folder+image_name+',format=qcow2,bus=virtio,size='+storage_size+' --vcpus='+cpu+' --ram='+ram+' --network bridge=virbr0 --os-type=linux --os-variant=rhel6 --import');
#AVX::CMD(source_device+':@'+ 'virt-install --connect qemu:///system --name='+vm_name+' --graphics=vnc --disk path='+image_destination_path+',format=qcow2,bus=virtio,size='+storage_size+' --vcpus='+cpu+' --ram='+ram+' --network bridge=virbr0 --os-type=linux --os-variant=rhel6 --import');

S
#path = os.path.dirname(os.path.abspath('__file__'))
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
python_path='python'
file_path = os.path.join(os.path.dirname(os.getcwd()), 'aps/helper/')

AVX::CMD("N/A:@ "+ 'mkdir -p '+logs);
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'palo_alto_config.py '+vm_name+' '+username+' '+password+' '+source_ip)