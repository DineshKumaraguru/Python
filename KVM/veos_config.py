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
child.expect('localhost login: ')
child.sendline('admin')
time.sleep(5)
child.sendline('enable')
child.sendline('configure terminal')
child.sendline('interface management 1')
child.sendline('ip address 192.168.133.231 255.255.255.0')
child.sendline('no shutdown')
child.sendline('exit')
time.sleep(5)
child.sendline('ip routing')
child.sendline('ip route 0.0.0.0/0 192.168.133.254')
child.sendline('username admin privilege 15 secret payoda@123')
time.sleep(5)
child.sendline('exit')
time.sleep(5)
child.sendline('copy scp:admin@192.168.133.211/mnt/flash/vEOS.swi flash:')
child.expect('Password: ')
child.sendline('payoda@123')
time.sleep(100)
child.sendline('boot system flash:vEOS.swi')
time.sleep(5)
child.sendline('write')
time.sleep(5)
child.sendline('reload now')
time.sleep(60)
child.sendline('virsh --connect qemu:///system start '+vm_name)
time.sleep(10)
child.sendline('virsh --connect qemu:///system attach-disk '+vm_name+' /'+vm_name+'_iso/Aboot-veos-2.0.8.iso hdc --type cdrom')
time.sleep(4)
child.sendline('exit')
print(child.before)
child.interact()