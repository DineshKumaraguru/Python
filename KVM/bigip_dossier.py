import pexpect
import time
import sys

vm_name = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
license_key = sys.argv[5]
time.sleep(400)
child = pexpect.spawn ('ssh '+username+'@'+ip)
child.expect (username+"@"+ip+"'s password: ")
child.sendline (password)
time.sleep(5)
child.sendline ('virsh console '+vm_name)
time.sleep(5)
child.sendline('\n')
time.sleep(5)
child.expect('localhost.localdomain login: ')
child.sendline('root')
child.expect('Password: ')
child.sendline('default')
time.sleep(5)
child.sendline('get_dossier -b '+license_key)
time.sleep(4)
child.sendline('exit')
time.sleep(5)
child.sendline('\n')
child.expect('localhost.localdomain login: ')
print(child.before)
child.sendcontrol('6')
child.sendcontrol(']')
time.sleep(4)
child.sendline("exit")