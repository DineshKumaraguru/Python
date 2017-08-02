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
pool_name = '<pool_name>'
pool_path = '/'+vm_name+'/pool/'
source_folder = '/home/Original_Image/';
qcow2_image_name='BIGIP-12.1.2.0.0.249.qcow2';

AVX::CMD(source_device+":@ " +'mv /bigip_org /'+vm_name);
AVX::CMD(source_device+':@'+'virsh pool-define-as '+pool_name+' dir - - - - '+pool_path);
AVX::CMD(source_device+':@'+'virsh pool-build '+pool_name);
AVX::CMD(source_device+':@'+'virsh pool-start '+pool_name);
AVX::CMD(source_device+':@'+'virsh pool-autostart '+pool_name);
AVX::CMD(source_device+':@'+'virt-install --name '+vm_name+' --ram '+ram+' --import --disk path='+pool_path+'BIGIP-12.1.2.0.0.249.qcow2,bus=virtio,format=qcow2 --vcpus '+cpu+' --os-type linux --network bridge=virbr0,model=virtio, --network bridge=br1,model=virtio,     --vnc --console pty,target_type=serial');
AVX::CMD(source_device+":@" +'mkdir -p /bigip_org/pool/');
AVX::CMD(source_device+":@" +'cp '+source_folder+qcow2_image_name+' /bigip_org/pool/');


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
license_key = '<license_key>'
vlan_name = '<vlan_name>'
admin_password = '<admin_password>'
time_zone = '<time_zone>'
username, password, source_ip = get_device_details(source_device)
logs='/home/appviewx/logs/'+vm_name+'/';


python_path = os.path.join(os.path.dirname(os.getcwd()), 'Python/bin/python',)
file_path = os.path.join(os.path.dirname(os.getcwd()), 'aps/helper/')
#python_path='python'

AVX::CMD("N/A:@ " +'mkdir -p '+logs);
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'bigip_dossier.py '+vm_name+' '+username+' '+password+' '+source_ip+' '+license_key+' > /tmp/'+license_key+'_raw.txt')
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'bigip_lisence.py '+username+' '+password+' '+source_ip+' '+license_key)
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'bigip_applylicense.py '+vm_name+' '+username+' '+password+' '+source_ip+' > '+logs+license_key+'_output.txt')
AVX::CMD("N/A:@ " + python_path + " " + file_path + 'bigip_provisioning.py '+vm_name+' '+username+' '+password+' '+source_ip+' '+vlan_name+' '+admin_password+' '+time_zone)