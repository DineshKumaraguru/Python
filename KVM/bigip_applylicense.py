import pexpect
import time
import sys

vm_name = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
time.sleep(600)
child = pexpect.spawn ('ssh '+username+'@'+ip)
child.expect (username+"@"+ip+"'s password: ")
child.sendline (password)
child.sendline ('virsh console '+vm_name+' --force')
time.sleep(5)
child.sendline('\n')
time.sleep(5)
child.expect('localhost.localdomain login: ')
child.sendline('root')
child.expect('Password: ')
child.sendline('default')
time.sleep(5)	
child.sendline('scp '+username+'@'+ip+':/var/tmp/bigip.license /config/')
time.sleep(4)
i = child.expect(['Are you sure you want to continue connecting (yes/no)?', username+"@"+ip+"'s password: "])
if i == 0:
    child.sendline('yes')
    time.sleep(4)
    child.expect (username+"@"+ip+"'s password: ")
    child.sendline (password)
else:
    child.sendline (password)
time.sleep(10)
child.sendline('reloadlic')
time.sleep(10)        
child.sendline('exit')
time.sleep(5)
child.sendcontrol('6')
child.sendcontrol(']')            
time.sleep(4)
print(child.before)  
child.interact()