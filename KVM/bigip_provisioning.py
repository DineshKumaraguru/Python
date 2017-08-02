import pexpect
import time
import sys
import paramiko
import json
import random
time.sleep(700)
mgmt_interface = 'virbr0'  # management interface of the device
bridge_interface = 'br1'

def get_device_ip(ssh,mac):
    stdin, stdout, stderr = ssh.exec_command('arp -e')
    output = stdout.read().decode()
    row_output = output.split('\n')
    ip = ''
    for entry in row_output:
        value = entry.split()
        try:
            if (value[2] == mac):
                ip = value[0]
        except :
            pass
    return ip

def pairs(iterable):
    i = iter(iterable)
    while True:
        yield next(i), next(i)


def get_interface_details(ssh, name):
    stdin, stdout, stderr = ssh.exec_command("virsh dumpxml " + str(name) + " | grep 'source bridge\|mac address' | awk '{print $2}'")
    tmp = stdout.read().decode()
    tmp_output = ''.join(val for val in tmp if (val.isalnum() or val == '=' or val == ' ' or val == '\n' or val == ":"))

    tmp_output = tmp_output.split('\n')

    tmp_final_output = [mac + ',' + bridge for mac, bridge in pairs(tmp_output)]
    maclist = {}
    for i in tmp_final_output:
        maclist[i.split(',')[1].split('=')[1]] = i.split(',')[0].split('=')[1]

    stdin1, stdout1, stderr1 = ssh.exec_command('brctl show')
    stdout1 = stdout1.read().decode()
    tmp1 = stdout1.split('\n')
    tmp_output1 = []
    for i in tmp1:
        if i.split('\t')[0] != '':
            if i.split('\t')[0][-2] != 'v':
                tmp_output1.append(i.split('\t')[0])
    output1 = tmp_output1[1:]
    # print(output1)
    stdin2, stdout2, stderr2 = ssh.exec_command("route -n")
    tmp2 = stdout2.read().decode()
    tmp_output2 = tmp2.split('\n')
    detail_list = []
    tmp_output2 = [x for x in tmp_output2 if x]
    tmp_output2 = tmp_output2[3:]
    for i in tmp_output2:
        detail_list.append([i.split()[0], i.split()[2], i.split()[7]])
    # print(detail_list)

    final_dict = {}
    for i in output1:
        for j in detail_list:
            if i in j:
                if maclist.get(str(i)):
                    final_dict[str(i)] = {'mac': maclist.get(str(i)), 'subnet': j[0] + '/' + str(
                        sum([bin(int(x)).count("1") for x in j[1].split(".")]))}
    return (final_dict, maclist)


def get_interface(out,mac):
    row_output = out.split('\\n')
    interface_name = ''
    for entry in row_output:
        value = entry.split()
        try:
            if (value[2] == mac):
                interface_name = value[0]
        except:
            pass
    return (interface_name)

def get_free_ip(outJson):
    out = outJson['interface_dict'][bridge_interface]['subnet']
    subnet_ip = out.split('/')[0]
    subnet_mask = out.split('/')[1]
    free_ip_array = subnet_ip.split('.')
    for key in range(0,len(free_ip_array)):
        if free_ip_array[key] =='0':
            free_ip_array[key] = str(random.randint(1,255))
    free_ip = '192'+'.'+free_ip_array[1]+'.'+free_ip_array[2]+'.'+free_ip_array[3]
    return (free_ip,subnet_mask)

def configure_bigip(ip,username,password,vm_name,outJson,vlan_name,admin_password,time_zone):
    child = pexpect.spawn('ssh ' + username + '@' + ip)
    child.expect(username + "@" + ip + "'s password: ")
    child.sendline(password)
    child.sendline('virsh console ' + vm_name + ' --force')
    time.sleep(5)
    child.sendline('\n')
    child.expect('localhost.localdomain login: ')
    child.sendline('root')
    time.sleep(5)
    child.expect('Password: ')
    child.sendline('default')
    time.sleep(5)
    child.sendline('tmsh show net interface all-properties')
    time.sleep(5)
    child.sendline('exit')
    time.sleep(5)
    child.expect('localhost.localdomain login: ')
    out = str(child.before)
    vlan_interface = get_interface(out, str(outJson['mac_addr']))
    free_ip,subnet_mask = get_free_ip(outJson)
    print(vlan_interface,free_ip,subnet_mask)
    #child.expect('[admin@localhost:Active:Standalone]')
    #child.sendline('tmsh modify /sys global-settings hostname ' + str(host_name))
    child.sendline('root')
    time.sleep(5)
    child.expect('Password: ')
    child.sendline('default')
    time.sleep(5)
    #time.sleep(2)
    child.sendline('tmsh modify auth user admin password ' + str(admin_password))
    time.sleep(2)
    child.sendline('tmsh modify auth user admin shell tmsh')
    time.sleep(2)
    child.sendline('tmsh modify auth user admin shell bash')
    time.sleep(2)
    child.sendline('tmsh modify sys ntp timezone '+str(time_zone))
    time.sleep(2)
    child.sendline('tmsh create net vlan ' + str(vlan_name).lower() + ' interfaces add { ' + str(vlan_interface) + ' { untagged } }')
    time.sleep(2)
    child.sendline('tmsh create net self ' + str(free_ip) + ' vlan ' + vlan_name + ' address ' + str(free_ip) + '/' + str(subnet_mask))
    time.sleep(2)
    print('tmsh create net vlan ' + str(vlan_name).lower() + ' interfaces add { ' + str(vlan_interface) + ' { untagged } }')
    print('tmsh create net self ' + str(free_ip) + ' vlan ' + vlan_name + ' address ' + str(free_ip) + '/' + str(subnet_mask))
    child.sendline('tmsh save sys config')
    time.sleep(5)
    #print(child.before)
    child.sendline('exit')
    time.sleep(5)
    child.sendline('\n')
    child.expect('localhost.localdomain login: ')
    child.sendcontrol('6')
    child.sendcontrol(']')
    time.sleep(4)
    child.sendline("exit")
    time.sleep(4)

try:
    host = sys.argv[4]  # ip of the kvm
    user = sys.argv[2]  # kvm user name
    password = sys.argv[3] # kvm password
    name = sys.argv[1]  # name of the vm
    admin_password = sys.argv[6]
    vlan_name = sys.argv[5]
    time_zone = sys.argv[7]

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=password, port=22)

    interface_detail_dict, mac_dict = get_interface_details(ssh, name)

    mgmt_mac_address = mac_dict[mgmt_interface]
    secondary_interface_mac_address = mac_dict[bridge_interface]

    ip = get_device_ip(ssh, mgmt_mac_address)

    outJson = {"mac_addr": secondary_interface_mac_address, 'interface_dict': interface_detail_dict, 'ip': ip}

    configure_bigip(host,user,password,name,outJson,vlan_name,admin_password,time_zone)

    ssh.close()
except Exception as e:
    print(e)