import paramiko
import os
import appviewx
import commands
import sys
import base64
import json
reload(appviewx)
path = os.path.dirname(os.path.abspath(__file__))

##
# Function for Decrypting Password
#
def decyrpt(EncryptedPassword, Key):
   decrypt_jar_path = path + '/../../properties/DecryptAPS.jar'
   java_path = path + '/../../jre/bin/java'
   cmd = java_path + ' -Dappviewx.property.path=/home/appviewx/AppViewX/properties/ -jar ' + decrypt_jar_path + ' ' + EncryptedPassword + ' ' + Key
   # run cli cmd to decrypt jar
   status, output = commands.getstatusoutput(cmd)
   password = ((output.strip('\n')).split(':')[0]).strip()
   #print output
   return password

##
# Function for getting Device details
#
def get_device_details(device_name):
    value = device_list.find_one({'name': device_name})
    username = value['access'][0]['userName']
    encPassword = value['access'][0]['password']
    key = value['access'][0]['key']
    vendor = value['vendor']
    ip = value['ip']
    password = decyrpt(encPassword, key)
    return username,password,vendor,ip

##
# Function for getting Device details
#
def ping(value,vendor_name,source_ip):
    if(vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint'):
        command = 'ping '
        for option in value['ping_options']:
            if(option == 'Count'):
                command += '-c '+str(value['ping_count'])+' '
            elif(option == 'Interval'):
                command += '-i '+str(value['ping_interval'])+' '
            elif(option == 'TTL'):
                command += '-t '+str(value['ping_ttl'])+' '
            elif(option == 'Interface'):
                command += '-I '+value['ping_interface']+' '
            else:
                command += ''
        command += value['destination_device']
    elif(vendor_name == 'A10'):
        command = 'ping source '+source_ip+' '
        for option in value['ping_options']:
            if(option == 'Count'):
                command += 'repeat '+str(value['ping_count'])+' '
            elif(option == 'Interval'):
                command += 'timeout '+str(value['ping_interval'])+' '
            elif(option == 'TTL'):
                command += 'ttl '+str(value['ping_ttl'])+' '
            else:
                command += ''
        command += value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping ' + value['destination_device'] + ' '
        for option in value['ping_options']:
            if (option == 'Count'):
                command +=str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command +=str(value['ping_interval']) + ' '
            else:
                command += ''
        command += '-d'
    elif (vendor_name == 'Citrix'):
        command = 'ping '
        for option in value['ping_options']:
            if (option == 'Count'):
                command += '-c ' + str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command += '-i ' + str(value['ping_interval']) + ' '
            elif (option == 'TTL'):
                command += '-t ' + str(value['ping_ttl']) + ' '
            else:
                command += ''
        command += value['destination_device']
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping ' + value['destination_device']
    elif (vendor_name == 'PaloAlto' ):
        command = 'ping '
        for option in value['ping_options']:
            if (option == 'Count'):
                command += 'count ' + str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command += 'interval ' + str(value['ping_interval']) + ' '
            elif (option == 'TTL'):
                command += 'ttl ' + str(value['ping_ttl']) + ' '
            else:
                command += ''
        command += 'source '+ source_ip+' host '+value['destination_device']
    elif (vendor_name == 'Juniper SRX'):
        command = 'ping '
        for option in value['ping_options']:
            if (option == 'Count'):
                command += '-c ' + str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command += '-i ' + str(value['ping_interval']) + ' '
            elif (option == 'TTL'):
                command += '-T ' + str(value['ping_ttl']) + ' '
            else:
                command += ''
        command += value['destination_device']
    else :
        command = ''
    #result = {"monitor_type": value['monitor_type'], "source_device": value['source_device'],"destination_device": value['destination_device'], "ping_count": value['ping_count'], "status": "","Output": ""}
    return (command)

##
# Function for generating ping6 command
#
def ping6(value,vendor_name):
    if(vendor_name == 'F5' or vendor_name == 'CheckPoint' or vendor_name == 'AVI'):
        command = 'ping6 '
        for option in value['ping6_options']:
            if(option == 'Count'):
                command += '-c '+str(value['ping_count'])+' '
            elif(option == 'Interval'):
                command += '-i '+str(value['ping_interval'])+' '
            elif(option == 'TTL'):
                command += '-t '+str(value['ping_ttl'])+' '
            elif(option == 'Interface'):
                command += '-I '+str(value['ping_interface'])+' '
            else:
                command += ''
        command += value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping6 ' + value['destination_device'] + ' '
        for option in value['ping6_options']:
            if (option == 'Count'):
                command +=str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command +=str(value['ping_interval']) + ' '
            else:
                command += ''
        command += '-d'
    elif (vendor_name == 'Citrix'):
        command = 'ping6 '
        for option in value['ping6_options']:
            if (option == 'Count'):
                command += '-c ' + str(value['ping_count']) + ' '
            elif (option == 'Interval'):
                command += '-i ' + str(value['ping_interval']) + ' '
            elif (option == 'TTL'):
                command += '-t ' + str(value['ping_ttl']) + ' '
            else:
                command += ''
        command += value['destination_device']
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping6 ' + value['destination_device']
    else :
        command = ''
    return (command)

##
# Function for generating ss command
#
def ss(value,vendor_name):
    if (vendor_name == 'F5' or vendor_name == 'AVI'):
        command = 'ss '
        for option in value['ss_options']:
            if (option == 'All'):
                command += '-a '
            elif (option == 'Resolve host name'):
                command += '-r '
            elif (option == 'Listening'):
                command += '-l '
            elif (option == 'Info'):
                command += '-i '
            elif (option == 'Summary'):
                command += '-s '
            elif (option == 'Tcp'):
                command += '-t '
            else :
                command += ''
        command += ' | grep localhost'
    else :
        command = ''
    return (command)

##
# Function for generating Netstat command
#
def netstat(value,vendor_name):
    if (vendor_name == 'F5'):
        command = 'netstat '
        for option in value['netstat_options']:
            if (option == 'All'):
                command += '-a '
            elif (option == 'Numeric address'):
                command += '-n '
            elif (option == 'Listening'):
                command += '-l '
            elif (option == 'Programs'):
                command += '-p '
            elif (option == 'Udp'):
                command += '-u '
            elif (option == 'Tcp'):
                command += '-t '
            elif (option == 'Unix'):
                command += '-x '
            else :
                command += ''
        command += ' | grep ntpd'
    elif (vendor_name == 'Citrix' or vendor_name == 'CheckPoint' or vendor_name == 'AVI'):
        command = 'netstat '
        for option in value['netstat_options']:
            if (option == 'All'):
                command += '-a '
            elif (option == 'Numeric address'):
                command += '-n '
            elif (option == 'Listening'):
                command += '-l '
            elif (option == 'Programs'):
                command += '-p '
            elif (option == 'Udp'):
                command += '-u '
            elif (option == 'Tcp'):
                command += '-t '
            elif (option == 'Unix'):
                command += '-x '
            else :
                command += ''
        command += ' | grep CONNECTED'
    elif (vendor_name == 'PaloAlto'):
        command = 'netstat '
        for option in value['netstat_options']:
            if (option == 'All'):
                command += 'all yes '
            elif (option == 'Numeric address'):
                command += 'numeric yes '
            elif (option == 'Listening'):
                command += 'listening yes '
            elif (option == 'Programs'):
                command += 'programs yes '
            else :
                command += ''
    else :
        command = ''
    return (command)

##
# Function for generating TracePath command
#
def tracepath(value,vendor_name):
    if (vendor_name == 'F5' or vendor_name == 'CheckPoint'):
        command = 'tracepath -nc '+value['destination_device']+'/'+str(value['port'])
    else:
        command = ''
    return (command)

##
# Function for generating Curl command
#
def curl(value,vendor_name):
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'IIS'):
        command = 'curl -k -X '+value['method']+' '+value['destination_device']
        if value['curl_authentication_options'] == 'Basic Auth':
            command += " -H 'authorization: Basic "+base64.encodestring('%s:%s' % (value['basic_auth_username'], value['basic_auth_password'])).replace('\n', '')+"'"
        elif value['curl_authentication_options'] =='OAuth':
            command_token = 'curl -X POST '+value['OAuth_url']+' -F client_id='+value['OAuth_client_id']+' -F client_secret='+value['OAuth_client_secret']+' -F grant_type=client_credentials'
            username, password, vendor_name, source_ip = get_device_details(value['source_device'])
            ssh.connect(source_ip, username=username, password=password)
            (stdin, stdout, stderr) = ssh.exec_command(command_token)
            command += " -H 'authorization: "
            if stdout.read():
                token = json.loads(stdout.read())
                command +=token['token_type']+" "+token['access_token']+"'"
        else :
            command +=''
        if value['method'] == 'POST' or value['method']== 'PUT':
            if value['curl_body']!='':
                command += " -d '"+value['curl_body']+"'"
        for key,value in value['curl_header_options']:
            command += ' -H "'+key+':'+value+'"'

    else :
        command =''
    return command

##
# Function for generating Nslookup command
#
def nslookup(value,vendor_name):
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint'):
        command = 'nslookup '
        for option in value['nslookup_options']:
            if option == 'query':
                command+=' -query='+value['nslookup_query_value']
            elif option == 'type':
                command+=' -type='+value['nslookup_type_value']
            elif option == 'port':
                command+=' -port='+str(value['nslookup_port_value'])
            elif option == 'timeout':
                command+=' -timeout='+str(value['nslookup_timeout_value'])
            else:
                command += ''
        command += ' '+value['destination_device']
    else :
        command =''
    return command

##
# Function for generating Netcat command
#
def netcat(monitor, vendor) :
	command = ''
	destination = monitor['destination_device']
	port = monitor['port']
	if vendor == 'F5' or vendor == 'AVI' :
		command = "nc "+ destination + " "+ port
		for option in monitor['nc_options']:
			if option == 's' :
				command +=' -s '+monitor['nc_source']
			elif option == 'w' :
				command +=' -w '+str(monitor['nc_wait_time'])
			else :
				command += ' -'+option
	return command
	
##
# Function for generating TraceRoute command
#
def traceroute(monitor, vendor) :
	command = ''
	destination = monitor['destination_device']
	#port = monitor['port']
	if vendor == 'F5' or vendor=='AVI' :
		command+='traceroute '+ destination
		for option in monitor['traceroute_options'] :
			if option == 'm' :
				command+=' -m '+str(monitor['traceroute_max_ttl'])
			elif option == 'q' :
				command+=' -q '+str(monitor['traceroute_nop_hop'])
			elif option == 'i' :
				command+=' -i '+monitor['traceroute_device_interface']
			elif option == 'w' :
				command+=' -w '+str(monitor['traceroute_wait_time'])
			elif option =='I' or option == 'T' or option =='U' or option =='n' :
				command += ' -'+option
	elif vendor == 'A10' :
		command+= 'traceroute'
		for option in monitor['traceroute_options'] :
			if option=='use-mgmt-port':
				command+=' '+option
		command+=' '+destination
	elif vendor == 'Fortinet' :
		command += 'execute traceroute '+destination
	elif vendor == 'Juniper SRX' :
		command += 'traceroute'
		for option in monitor['traceroute_options'] :
			if option == 'gateway' :
				command+=' gateway '+monitor['traceroute_gateway']
			elif option == 'i' :
				command+=' interface '+monitor['traceroute_device_interface']
			elif option == 'm' :
				command+=' ttl '+str(monitor['traceroute_max_ttl'])
			elif option=='inet' : 
				command+=' inet '+monitor['traceroute_inet_destination']
			elif option=='inet6' : 
				command+=' inet6 '+monitor['traceroute_inet6_destination']
			elif option == 'source' :
				command+=' source '+monitor['traceroute_source']
	elif vendor == 'CheckPoint' :
		command += 'traceroute'
		for option in monitor['traceroute_options'] :
			if option == 'i' :
				command+=' -i '+monitor['traceroute_device_interface']
			elif option == 'source' :
				command+=' -s '+monitor['traceroute_source']
			elif option=='I' or option=='T' or option=='U' or option=='n' :
				command+= ' - '+option
		command+=' '+destination
	elif vendor=='Radware':
		command+='traceroute '+destination
		for option in monitor['traceroute_options'] :
			if option=='use-mgmt-port' :
				command+=' -mgmt'
			elif option=='max-hops':
				command+=' '+str(monitor['traceroute_max_hops'])
			elif option=='delay':
				command+=' '+str(monitor['traceroute_delay'])
	elif vendor=='PaloAlto' :
		command+='traceroute'
		for option in montior['traceroute_options'] :
			if option == 'gateway' :
				command+=' gateway '+monitor['traceroute_gateway']
			elif option=='m' :
				command+=' max-ttl '+monitor['traceroute_max_ttl']
			elif option=='n' :
				command+=' no-resolve yes'
			elif option=='source' :
				command+=' source '+monitor['traceroute_source']
			elif option=='w' :
				command+=' wait '+monitor['traceroute_wait_time']
			elif option=='pause' :
				command+=' pause '+monitor['traceroute_pause']
		if port!='' :
			command+=' port '+port	
		command+=' host '+destination
	return command

##
# Function for generating TraceRoute6 command
#
def traceroute6(monitor, vendor) :
	command = ''
	destination = monitor['destination_device']
	if vendor == 'F5' :
		command+='traceroute6 '+destination
		for option in monitor['traceroute6_options']:
			if option=='n' :
				command+=' -n'
			elif option=='w' :
				command+=' -w '+monitor['traceroute6_wait_time']
			elif option=='q' :
				command+= ' -q '+monitor['traceroute6_nop_hop']
	return command

##
# Input data from Form
#
form_input = [
{"monitor_type":"PING","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"PING6","source_device":"AVI_192.168.40.221","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"NETSTAT","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED"},
{"monitor_type":"SS","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED"},
{"monitor_type":"TRACEPATH","source_device":"192.168.40.150","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80},
{'monitor_type':'NETCAT','source_device':'AVI_192.168.40.221', 'destination_device':'10.10.100.48',"netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80},
{'monitor_type':'TRACEROUTE','source_device':'AVI_192.168.40.221', 'destination_device':'192.168.4.135',"traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.152","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'OAuth','OAuth_url':'https://graph.facebook.com/oauth/access_token','OAuth_client_id':'476746925996549','OAuth_client_secret':'8d62d8e6fc7f51ac64fda950d09c99d7','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'Basic Auth','basic_auth_username':'admin','basic_auth_password':'payoda@123','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'No Auth','curl_header_options':[],'curl_body':''},
{'monitor_type':'NSLOOKUP','source_device':'AVI_192.168.40.221','destination_device':'payoda.com',"nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'TRACEROUTE6','source_device':'AVI_192.168.40.221','destination_device':'192.168.4.135',"nslookup_options":['query','type','port','timeout'],"traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3},
{'monitor_type':'SNMPWALK','source_device':'AVI_192.168.40.221','destination_device':'192.168.4.135',"version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
{'monitor_type':'SNMPWALK','source_device':'AVI_192.168.40.221','destination_device':'192.168.4.135',"version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
]

##
# Connect to Appviewx Database
#
try :
   client = appviewx.db_connection()
   device_list = client.appviewx.device
except Exception as e:
   print e
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for value in form_input:
        username, password, vendor_name, source_ip = get_device_details(value['source_device'])
        #ssh.connect(source_ip, username=username, password=password)
        if(value['monitor_type'] == 'PING'):
            command = ping(value,vendor_name,source_ip)
        elif value['monitor_type'] == 'NETCAT':
            command = netcat(value, vendor_name)
        elif value['monitor_type'] == 'TRACEROUTE':
            command = traceroute(value, vendor_name)
        elif value['monitor_type'] == 'TRACEROUTE6':
            command = traceroute6(value, vendor_name)
        elif value['monitor_type'] == 'TRACEPATH':
            command = tracepath(value, vendor_name)
        elif value['monitor_type'] == 'NETSTAT':
            command = netstat(value, vendor_name)
        elif value['monitor_type'] == 'SS':
            command = ss(value, vendor_name)
        elif value['monitor_type'] == 'PING6':
            command = ping6(value, vendor_name)
        elif value['monitor_type'] == 'CURL':
            command = curl(value, vendor_name)
        elif value['monitor_type'] == 'NSLOOKUP':
            command = nslookup(value, vendor_name)
        else:
            command=''
        if (command != ''):
            if len(sys.argv)>1 and sys.argv[1]=='preview':
                print source_ip, ' ', command
            else :
                print source_ip, ' ', command
                ssh.connect(source_ip, username=username, password=password)
                (stdin, stdout, stderr) = ssh.exec_command(command)
                print stderr.read()
                print stdout.read()
except Exception as e :
    print (e)
finally:
    ssh.close()
