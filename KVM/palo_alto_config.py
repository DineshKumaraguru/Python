import pexpect
import time
import sys
vm_name = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
time.sleep(400)
child = pexpect.spawn ('ssh '+username+'@'+ip)
fout = open('/home/appviewx/logs/'+vm_name+'/log.txt','wb')
child.logfile = fout
child.expect (username+"@"+ip+"'s password: ")
child.sendline (password)
time.sleep(5)
child.sendline('virsh console '+vm_name)
time.sleep(5)
child.sendline('\n')
child.expect('PA-VM login: ')
child.sendline('admin')
child.expect('Password: ')
child.sendline('admin')
child.expect('admin@PA-VM> ')
child.sendline('configure')
child.sendline('set deviceconfig system ip-address 192.168.133.232 netmask 255.255.255.0 default-gateway 192.168.133.254 dns-setting servers primary 8.8.8.8')
child.sendline('commit')
time.sleep(20)
child.sendline('set network interface ethernet ethernet1/1 layer3 ip 192.168.250.2/24')
child.sendline('set zone trust network layer3 ethernet1/1')
child.sendline('set network virtual-router default interface ethernet1/1')
child.sendline('set network interface ethernet ethernet1/2 layer3 ip 192.168.251.1/24')
child.sendline('set zone untrust network layer3 ethernet1/2')
child.sendline('set network virtual-router default interface ethernet1/2')
child.sendline('set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0 nexthop ip-address 172.16.77.169')
child.sendline('set network profiles interface-management-profile allow_ping_ssh ping yes ssh yes')
child.sendline('set network interface ethernet ethernet1/1 layer3 interface-management-profile allow_ping_ssh')
child.sendline('set network profiles interface-management-profile allow_ping ping yes')
child.sendline('set network interface ethernet ethernet1/2 layer3 interface-management-profile allow_ping')
child.sendline('commit')
time.sleep(20)
child.sendline('exit')
time.sleep(5)
child.sendcontrol('6')
child.sendcontrol(']')
time.sleep(5)
child.sendline('exit')
print child.before
child.interact()