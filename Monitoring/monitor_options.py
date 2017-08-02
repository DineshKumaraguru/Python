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


def frame_options(value,vendor_name):
    command_option = ''
    type= value['monitor_type'].lower()+'_options'
    for option in value[type]:
        if vendor_name in options[type][option]['option_key']:
            option_value = options[type][option]['option_key'][vendor_name]
            command_option += option_value
        else:
            option_value = options[type][option]['option_key']['default']
            command_option += option_value
        if 'value_key' in options[type][option] and option_value !="":
            command_option += ' '+str(value[options[type][option]['value_key']])+' '
        else:
            command_option += ' '
    return command_option

def ping(value,vendor_name,source_ip):
    command_option = frame_options(value,vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint' or vendor_name == 'Citrix' or vendor_name == 'Juniper SRX'):
        command = 'ping '+command_option+value['destination_device']
    elif (vendor_name == 'A10'):
        command = 'ping source ' + source_ip + ' '+command_option+value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping ' + value['destination_device'] + ' '+command_option+'-d'
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping ' + value['destination_device']
    elif (vendor_name == 'PaloAlto'):
        command = 'ping '+command_option+'source ' + source_ip + ' host ' + value['destination_device']
    else :
        command = ''
    return command

def ping6(value,vendor_name):
    command_option = frame_options(value,vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint' or vendor_name == 'Citrix'):
        command = 'ping6 '+command_option+value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping6 ' + value['destination_device'] + ' '+command_option+'-d'
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping6 ' + value['destination_device']
    else :
        command = ''
    return command

def ss(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI'):
        command = 'ss '+command_option+' | grep '+value['grep']
    else :
        command = ''
    return (command)

def tracepath(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'CheckPoint'):
        command = 'tracepath '+command_option+value['destination_device']+'/'+str(value['port'])
    else:
        command = ''
    return (command)

def netstat(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'Citrix' or vendor_name == 'CheckPoint' or vendor_name == 'AVI' or vendor_name == 'PaloAlto'):
        command = 'netstat '+command_option+' | grep '+value['grep']
    else :
        command = ''
    return (command)

def nslookup(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint'):
        command = 'nslookup '+command_option+value['destination_device']
    else :
        command =''
    return command

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

def netcat(value,vendor_name,sourceip) :
    command_option = frame_options(value, vendor_name)
    if 'source_ip_address' in value['netcat_options']:
        command_option += '-s '+sourceip
    if vendor_name == 'F5' or vendor_name=='AVI':
        command = 'nc '+command_option+' '+value['destination_device']+' '+str(value['port'])
    else:
        command = ''
    return (command)

def traceroute(value,vendor_name) :
    command_option = frame_options(value, vendor_name)
    if vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name=='Radware':
        command = 'traceroute ' +value['destination_device']+' '+command_option
    elif vendor_name == 'Fortinet':
        command = 'execute traceroute ' +value['destination_device']
    elif vendor_name == 'A10' or vendor_name == 'CheckPoint' or vendor_name=='Citrix'  :
        command = 'traceroute ' +command_option+ value['destination_device']
    elif vendor_name == 'Juniper SRX' or vendor_name=='PaloAlto' :
        command = 'traceroute ' + command_option
    else :
        command = ''
    return command

def traceroute6(value,vendor_name) :
    command_option = frame_options(value, vendor_name)
    if vendor_name == 'F5' or vendor_name == 'AVI' :
        command = 'traceroute6 ' +value['destination_device']+' '+command_option
    elif vendor_name == 'Citrix':
        command = 'traceroute6 ' + command_option + value['destination_device']
    else :
        command = ''
    return command

def snmpwalk(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    command = 'snmpwalk -v'+value['version']+' '+command_option+' '+value['destination_device']+' '+value['oid']
    return command

"""
form_input = [
{"monitor_type":"PING","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"PING6","source_device":"AVI_192.168.40.221","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"NETSTAT","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED"},
{"monitor_type":"SS","source_device":"AVI_192.168.40.221","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED"},
{"monitor_type":"TRACEPATH","source_device":"192.168.40.150","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80},
{'monitor_type':'NETCAT','source_device':'AVI_192.168.40.221', 'destination_device':'10.10.100.48',"netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','source_ip_address','timeout'],"netcat_timeout":10,"port":80},
{'monitor_type':'TRACEROUTE','source_device':'AVI_192.168.40.221', 'destination_device':'192.168.4.135',"traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.152","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'OAuth','OAuth_url':'https://graph.facebook.com/oauth/access_token','OAuth_client_id':'476746925996549','OAuth_client_secret':'8d62d8e6fc7f51ac64fda950d09c99d7','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'Basic Auth','basic_auth_username':'admin','basic_auth_password':'payoda@123','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'No Auth','curl_header_options':[],'curl_body':''},
{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['query','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
#{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
#{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'TRACEROUTE6','source_device':'AVI_192.168.40.221','destination_device':'::1',"nslookup_options":['query','type','port','timeout'],"traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3},
{'monitor_type':'SNMPWALK','source_device':'AVI_192.168.40.221','destination_device':'192.168.4.135',"version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
{'monitor_type':'SNMPWALK','source_device':'AVI_192.168.40.221','destination_device':'192.168.4.135',"version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
]
"""

form_input = [
{"monitor_type":"PING","source_device":"bigip152.payoda.com","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"PING6","source_device":"bigip152.payoda.com","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0"},
{"monitor_type":"NETSTAT","source_device":"bigip152.payoda.com","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED"},
{"monitor_type":"SS","source_device":"bigip152.payoda.com","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED"},
{"monitor_type":"TRACEPATH","source_device":"bigip152.payoda.com","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80},
{'monitor_type':'NETCAT','source_device':'bigip152.payoda.com', 'destination_device':'10.10.100.48',"netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','source_ip_address','timeout'],"netcat_timeout":10,"port":80},
{'monitor_type':'TRACEROUTE','source_device':'bigip152.payoda.com', 'destination_device':'192.168.4.135',"traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.152","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80},
{'monitor_type':'CURL','method':'GET','source_device':'AVI_192.168.40.221', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'OAuth','OAuth_url':'https://graph.facebook.com/oauth/access_token','OAuth_client_id':'476746925996549','OAuth_client_secret':'8d62d8e6fc7f51ac64fda950d09c99d7','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'bigip152.payoda.com', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'Basic Auth','basic_auth_username':'admin','basic_auth_password':'payoda@123','curl_header_options':[],'curl_body':''},
{'monitor_type':'CURL','method':'GET','source_device':'bigip152.payoda.com', 'destination_device':'https://192.168.40.152/','curl_authentication_options':'No Auth','curl_header_options':[],'curl_body':''},
{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['query','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'NSLOOKUP','source_device':'bigip152.payoda.com','destination_device':'payoda.com',"nslookup_options":['type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10},
{'monitor_type':'TRACEROUTE6','source_device':'bigip152.payoda.com','destination_device':'::1',"traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3},
{'monitor_type':'SNMPWALK','source_device':'bigip152.payoda.com','destination_device':'192.168.4.135',"version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
{'monitor_type':'SNMPWALK','source_device':'bigip152.payoda.com','destination_device':'192.168.4.135',"version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45"},
]


options = {
"ping_options":{
"Count":{"option_key":{"default":"-c","A10":"repeat","Radware":" ","PaloAlto":"count","Juniper SRX":"count"},"value_key":"ping_count"},
"Interval":{"option_key":{"default":"-i","A10":"timeout","Radware":" ","PaloAlto":"interval","Juniper SRX":"interval"},"value_key":"ping_interval"},
"TTL":{"option_key":{"default":"-t","A10":"ttl","Radware":"","PaloAlto":"ttl","Juniper SRX":"ttl"},"value_key":"ping_ttl"},
"Interface":{"option_key":{"default":"-I","A10":"","Radware":"","Citrix":"","PaloAlto":"","Juniper SRX":""},"value_key":"ping_interface"},
"Inet":{"option_key":{"default":"","Juniper SRX":"inet"}},
"Inet6":{"option_key":{"default":"","Juniper SRX":"inet6"}},
"wait_time":{"option_key":{"default":"","Juniper SRX":"wait"},"value_key":"ping_wait_time"},
},
"ping6_options":{
"Count":{"option_key":{"default":"-c","Radware":" "},"value_key":"ping_count"},
"Interval":{"option_key":{"default":"-i","Radware":" "},"value_key":"ping_interval"},
"TTL":{"option_key":{"default":"-t","Radware":""},"value_key":"ping_ttl"},
"Interface":{"option_key":{"default":"-I","Radware":"","Citrix":""},"value_key":"ping_interface"},
},
"ss_options":{
"All":{"option_key":{"default":"-a"}},
"Resolve host name":{"option_key":{"default":"-r"}},
"Listening":{"option_key":{"default":"-l"}},
"Info":{"option_key":{"default":"-i"}},
"Summary":{"option_key":{"default":"-s"}},
"Tcp":{"option_key":{"default":"-t"}},
},
"netstat_options":{
"All":{"option_key":{"default":"-a","PaloAlto":"all yes"}},
"Numeric address":{"option_key":{"default":"-n","PaloAlto":"numeric yes"}},
"Listening":{"option_key":{"default":"-l","PaloAlto":"listening yes"}},
"Programs":{"option_key":{"default":"-p","PaloAlto":"programs yes"}},
"Udp":{"option_key":{"default":"-u","PaloAlto":""}},
"Tcp":{"option_key":{"default":"-t","PaloAlto":""}},
"Unix":{"option_key":{"default":"-x","PaloAlto":""}},
},
"nslookup_options":{
"query":{"option_key":{"default":"-query="},"value_key":"nslookup_query_value"},
"type":{"option_key":{"default":"-type="},"value_key":"nslookup_type_value"},
"port":{"option_key":{"default":"-port="},"value_key":"nslookup_port_value"},
"timeout":{"option_key":{"default":"-timeout="},"value_key":"nslookup_timeout_value"},
},
"tracepath_options":{
"Do not look up host names":{"option_key":{"default":"-n"}},
"Set the initial packet length":{"option_key":{"default":"-l"}},
},
"netcat_options":{
"Do not do any DNS or service lookups":{"option_key":{"default":"-n"}},
"verbose":{"option_key":{"default":"-v"}},
"UDP":{"option_key":{"default":"-u"}},
"scan for listening daemons":{"option_key":{"default":"-z"}},
"listen for an incoming connection":{"option_key":{"default":"-l"}},
"source_ip_address":{"option_key":{"default":""}},
"timeout":{"option_key":{"default":"-w"},"value_key":"netcat_timeout"},
},
"traceroute_options":{
"Icmp echo for traceroute":{"option_key":{"default":"-I","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Tcp sync for traceroute":{"option_key":{"default":"-T","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Udp packet for tarceroute":{"option_key":{"default":"-U","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Interface":{"option_key":{"default":"-i","A10":"","Juniper SRX":"interface","Radware":"","PaloAlto":"","Citrix":""},"value_key":"traceroute_interface"},
"TTL":{"option_key":{"default":"-m","A10":"","Juniper SRX":"ttl","Radware":"","PaloAlto":"","Citrix":"","CheckPoint":""},"value_key":"traceroute_ttl"},
"Do not resolve hostname":{"option_key":{"default":"-n","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"no-resolve yes"}},
"Wait time":{"option_key":{"default":"-w","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"wait","CheckPoint":""},"value_key":"traceroute_wait_time"},
"Number of probe packets per hop":{"option_key":{"default":"-q","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","CheckPoint":""},"value_key":"traceroute_probe_packets_per_hop"},
"Use Mgmt port":{"option_key":{"default":"","A10":"use-mgmt-port","Radware":"-mgmt"}},
"Gateway":{"option_key":{"default":"","Juniper SRX":"gateway","PaloAlto":"gateway"},"value_key":"traceroute_gateway"},
"Inet":{"option_key":{"default":"","Juniper SRX":"inet"},"value_key":"destination_device"},
"Inet6":{"option_key":{"default":"","Juniper SRX":"inet6"},"value_key":"destination_device"},
"Source":{"option_key":{"default":"","Juniper SRX":"source","PaloAlto":"source","CheckPoint":"-s"},"value_key":"traceroute_source"},
"max-hops":{"option_key":{"default":"","Radware":" "},"value_key":"traceroute_max_hops"},
"Delay":{"option_key":{"default":"","Radware":" "},"value_key":"traceroute_delay"},
"Pause":{"option_key":{"default":"","PaloAlto":"pause"},"value_key":"traceroute_pause"},
"Port":{"option_key":{"default":"","PaloAlto":"port","Citrix":"-p"},"value_key":"port"},
"Host":{"option_key":{"default":"","PaloAlto":"host"},"value_key":"destination_device"},
},
"traceroute6_options":{
"Do not resolve hostname":{"option_key":{"default":"-n"}},
"Wait time":{"option_key":{"default":"-w"},"value_key":"traceroute6_wait_time"},
"Number of probe packets per hop":{"option_key":{"default":"-q"},"value_key":"traceroute_probe_packets_per_hop"},
},
"snmpwalk_options":{
"community":{"option_key":{"default":"-c"},"value_key":"snmpwalk_community"},
"username":{"option_key":{"default":"-u"},"value_key":"snmpwalk_username"},
"authentication hash":{"option_key":{"default":"-a"},"value_key":"snmpwalk_hash"},
"authentication type":{"option_key":{"default":"-l"},"value_key":"snmpwalk_auth_type"},
"encryption":{"option_key":{"default":"-x"},"value_key":"snmpwalk_encryption"},
"auth phrase":{"option_key":{"default":"-A"},"value_key":"snmpwalk_auth_phrase"},
"privaphrase":{"option_key":{"default":"-X"},"value_key":"snmpwalk_priva_phrase"},
}
}

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
        if value['monitor_type'] == 'PING':
            command = ping(value, vendor_name, source_ip)
        elif value['monitor_type'] == 'NETCAT':
            command = netcat(value, vendor_name, source_ip)
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
        elif value['monitor_type'] == 'SNMPWALK':
            command = snmpwalk(value, vendor_name)
        else:
            command = ''
        if (command != ''):
            if len(sys.argv) > 1 and sys.argv[1] == 'preview':
                print vendor_name, source_ip, ' ', command
            else:
                print source_ip, ' ', command
                ssh.connect(source_ip, username=username, password=password)
                (stdin, stdout, stderr) = ssh.exec_command(command)
                print stderr.read()
                print stdout.read()
except Exception as e :
    print (e)
finally:
    ssh.close()
"""
import paramiko
import os
import commands
import sys

def get_device_details(value):
    #value = device_list.find_one({'name': device_name})
    username = value['username']
    encPassword = value['password']
    #key = value['access'][0]['key']
    vendor = value['vendor_name']
    ip = value['source_device']
    password = value['password']
    #password = decyrpt(encPassword, key)
    return username,password,vendor,ip

def frame_options(value,vendor_name):
    command_option = ''
    type= value['monitor_type'].lower()+'_options'
    for option in value[type]:
        if vendor_name in options[type][option]['option_key']:
            option_value = options[type][option]['option_key'][vendor_name]
            command_option += option_value
        else:
            option_value = options[type][option]['option_key']['default']
            command_option += option_value
        if 'value_key' in options[type][option] and option_value !="":
            command_option += ' '+str(value[options[type][option]['value_key']])+' '
        else:
            command_option += ' '
    return command_option

def ping(value,vendor_name,source_ip):
    command_option = frame_options(value,vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint' or vendor_name == 'Citrix' or vendor_name == 'Juniper SRX'):
        command = 'ping '+command_option+value['destination_device']
    elif (vendor_name == 'A10'):
        command = 'ping source ' + source_ip + ' '+command_option+value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping ' + value['destination_device'] + ' '+command_option+'-d'
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping ' + value['destination_device']
    elif (vendor_name == 'PaloAlto'):
        command = 'ping '+command_option+'source ' + source_ip + ' host ' + value['destination_device']
    else :
        command = ''
    return command

def ping6(value,vendor_name):
    command_option = frame_options(value,vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint' or vendor_name == 'Citrix'):
        command = 'ping6 '+command_option+value['destination_device']
    elif (vendor_name == 'Radware'):
        command = 'ping6 ' + value['destination_device'] + ' '+command_option+'-d'
    elif (vendor_name == 'Fortinet'):
        command = 'execute ping6 ' + value['destination_device']
    else :
        command = ''
    return command

def ss(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI'):
        command = 'ss '+command_option+' | grep '+value['grep']
    else :
        command = ''
    return (command)

def tracepath(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'CheckPoint'):
        command = 'tracepath '+command_option+value['destination_device']+'/'+str(value['port'])
    else:
        command = ''
    return (command)

def netstat(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'Citrix' or vendor_name == 'CheckPoint' or vendor_name == 'AVI' or vendor_name == 'PaloAlto'):
        command = 'netstat '+command_option+' | grep '+value['grep']
    else :
        command = ''
    return (command)

def nslookup(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    if (vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name == 'CheckPoint'):
        command = 'nslookup '+command_option+value['destination_device']
    else :
        command =''
    return command

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

def netcat(value,vendor_name,sourceip) :
    command_option = frame_options(value, vendor_name)
    if 'source_ip_address' in value['netcat_options']:
        command_option += '-s '+sourceip
    if vendor_name == 'F5' or vendor_name=='AVI':
        command = 'nc '+command_option+' '+value['destination_device']+' '+str(value['port'])
    else:
        command = ''
    return (command)

def traceroute(value,vendor_name) :
    command_option = frame_options(value, vendor_name)
    if vendor_name == 'F5' or vendor_name == 'AVI' or vendor_name=='Radware':
        command = 'traceroute ' +value['destination_device']+command_option
    elif vendor_name == 'Fortinet':
        command = 'execute traceroute ' +value['destination_device']
    elif vendor_name == 'A10' or vendor_name == 'CheckPoint' or vendor_name=='Citrix'  :
        command = 'traceroute ' +command_option+ value['destination_device']
    elif vendor_name == 'Juniper SRX' or vendor_name=='PaloAlto' :
        command = 'traceroute ' + command_option
    else :
        command = ''
    return command

def traceroute6(value,vendor_name) :
    command_option = frame_options(value, vendor_name)
    if vendor_name == 'F5' or vendor_name == 'AVI' :
        command = 'traceroute6 ' +value['destination_device']+command_option
    elif vendor_name == 'Citrix':
        command = 'traceroute6 ' + command_option + value['destination_device']
    else :
        command = ''
    return command

def snmpwalk(value,vendor_name):
    command_option = frame_options(value, vendor_name)
    command = 'snmpwalk -v'+value['version']+' '+command_option+' '+value['destination_device']+' '+value['oid']
    return command

form_input = [
{"monitor_type":"PING","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"F5"},
{"monitor_type":"PING","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"A10"},
{"monitor_type":"PING","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"AVI"},
{"monitor_type":"PING","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Radware"},
{"monitor_type":"PING","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Citrix"},
{"monitor_type":"PING","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"CheckPoint"},
{"monitor_type":"PING","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Fortinet"},
{"monitor_type":"PING","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"PaloAlto"},
{"monitor_type":"PING","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","ping_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Juniper SRX"},

{"monitor_type":"PING6","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"F5"},
{"monitor_type":"PING6","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"A10"},
{"monitor_type":"PING6","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"AVI"},
{"monitor_type":"PING6","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Radware"},
{"monitor_type":"PING6","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Citrix"},
{"monitor_type":"PING6","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"CheckPoint"},
{"monitor_type":"PING6","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Fortinet"},
{"monitor_type":"PING6","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"PaloAlto"},
{"monitor_type":"PING6","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"::1","ping6_options":['Count','Interval','Interface','TTL'],"ping_count":3,"ping_interval":2,"ping_ttl":10,"ping_interface":"eth0","vendor_name":"Juniper SRX"},

{"monitor_type":"NETSTAT","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"F5"},
{"monitor_type":"NETSTAT","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"A10"},
{"monitor_type":"NETSTAT","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"AVI"},
{"monitor_type":"NETSTAT","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"Radware"},
{"monitor_type":"NETSTAT","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"Citrix"},
{"monitor_type":"NETSTAT","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"CheckPoint"},
{"monitor_type":"NETSTAT","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"Fortinet"},
{"monitor_type":"NETSTAT","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"PaloAlto"},
{"monitor_type":"NETSTAT","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","netstat_options":['All','Numeric address','Listening','Programs','Udp','Tcp','Unix'],"grep":"CONNECTED","vendor_name":"Juniper SRX"},

{"monitor_type":"SS","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"F5"},
{"monitor_type":"SS","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"A10"},
{"monitor_type":"SS","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"AVI"},
{"monitor_type":"SS","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"Radware"},
{"monitor_type":"SS","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"Citrix"},
{"monitor_type":"SS","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"CheckPoint"},
{"monitor_type":"SS","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"Fortinet"},
{"monitor_type":"SS","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"PaloAlto"},
{"monitor_type":"SS","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","ss_options":['All','Resolve host name','Listening','Info','Summary','Tcp'],"grep":"CONNECTED","vendor_name":"Juniper SRX"},

{"monitor_type":"TRACEPATH","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"F5"},
{"monitor_type":"TRACEPATH","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"A10"},
{"monitor_type":"TRACEPATH","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"AVI"},
{"monitor_type":"TRACEPATH","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"Radware"},
{"monitor_type":"TRACEPATH","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"Citrix"},
{"monitor_type":"TRACEPATH","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"CheckPoint"},
{"monitor_type":"TRACEPATH","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"Fortinet"},
{"monitor_type":"TRACEPATH","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"PaloAlto"},
{"monitor_type":"TRACEPATH","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","tracepath_options":['Do not look up host names','Set the initial packet length'],"port":80,"vendor_name":"Juniper SRX"},

{"monitor_type":"NSLOOKUP","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"F5"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"A10"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"AVI"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"Radware"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"Citrix"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"CheckPoint"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"Fortinet"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"PaloAlto"},
{"monitor_type":"NSLOOKUP","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","nslookup_options":['query','type','port','timeout'],"nslookup_query_value":"mx","nslookup_type_value":"ns","nslookup_port_value":56,"nslookup_timeout_value":10,"vendor_name":"Juniper SRX"},

{"monitor_type":"NETCAT","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"F5"},
{"monitor_type":"NETCAT","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"A10"},
{"monitor_type":"NETCAT","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"AVI"},
{"monitor_type":"NETCAT","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"Radware"},
{"monitor_type":"NETCAT","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"Citrix"},
{"monitor_type":"NETCAT","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"CheckPoint"},
{"monitor_type":"NETCAT","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"Fortinet"},
{"monitor_type":"NETCAT","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"PaloAlto"},
{"monitor_type":"NETCAT","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","netcat_options":['Do not do any DNS or service lookups','verbose','UDP','scan for listening daemons','listen for an incoming connection','source_ip_address','timeout'],"netcat_timeout":10,"port":80,"vendor_name":"Juniper SRX"},

{"monitor_type":"TRACEROUTE","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.152","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"F5"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.62","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"A10"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.221","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"AVI"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.40.203","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"Radware"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.41.84","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"Citrix"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.55.59","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"CheckPoint"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.41.44","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"Fortinet"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.55.75","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"PaloAlto"},
{"monitor_type":"TRACEROUTE","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","traceroute_options":['Icmp echo for traceroute','Tcp sync for traceroute','Udp packet for tarceroute','Interface','TTL','Do not resolve hostname','Wait time','Number of probe packets per hop','Use Mgmt port','Gateway','Inet','Inet6','Source','max-hops','Delay','Pause','Port','Host'],"traceroute_interface":"eth0","traceroute_ttl":10,"traceroute_wait_time":5,"traceroute_probe_packets_per_hop":3,"traceroute_gateway":"192.168.7.69","traceroute_source":"192.168.55.34","traceroute_max_hops":30,"traceroute_delay":10,"traceroute_pause":1,"port":80,"vendor_name":"Juniper SRX"},

{"monitor_type":"TRACEROUTE6","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"F5"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"A10"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"AVI"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"Radware"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"Citrix"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"CheckPoint"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"Fortinet"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"PaloAlto"},
{"monitor_type":"TRACEROUTE6","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","traceroute6_options":['Do not resolve hostname','Wait time','Number of probe packets per hop'],"traceroute6_wait_time":5,"traceroute_probe_packets_per_hop":3,"vendor_name":"Juniper SRX"},

{"monitor_type":"SNMPWALK","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"F5"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"A10"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"AVI"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Radware"},
{"monitor_type":"SNMPWALK","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Citrix"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"CheckPoint"},
{"monitor_type":"SNMPWALK","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Fortinet"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"PaloAlto"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","version":"2c","snmpwalk_options":['community'],"snmpwalk_community":"public","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Juniper SRX"},

{"monitor_type":"SNMPWALK","source_device":"192.168.40.152","username":"admin","password":"admin","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"F5"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.62","username":"admin","password":"a10","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"A10"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.221","username":"admin","password":"payoda@123","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"AVI"},
{"monitor_type":"SNMPWALK","source_device":"192.168.40.203","username":"admin","password":"admin","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Radware"},
{"monitor_type":"SNMPWALK","source_device":"192.168.41.84","username":"nsroot","password":"nsroot","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Citrix"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.59","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"CheckPoint"},
{"monitor_type":"SNMPWALK","source_device":"192.168.41.44","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Fortinet"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.75","username":"admin","password":"Payoda@234","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"PaloAlto"},
{"monitor_type":"SNMPWALK","source_device":"192.168.55.34","username":"root","password":"Payoda@234","destination_device":"192.168.4.135","version":"3","snmpwalk_options":['username','authentication hash','authentication type','encryption','auth phrase','privaphrase'],"snmpwalk_username":"snmpuser","snmpwalk_hash":"SHA","snmpwalk_auth_type":"authPriv","snmpwalk_encryption":"AES","snmpwalk_auth_phrase":"snmpauth","snmpwalk_priva_phrase":"snmppriv","oid":".1.3.6.1.4.1.3375.2.1.1.2.1.45","vendor_name":"Juniper SRX"},
]

options = {
"ping_options":{
"Count":{"option_key":{"default":"-c","A10":"repeat","Radware":" ","PaloAlto":"count","Juniper SRX":"count"},"value_key":"ping_count"},
"Interval":{"option_key":{"default":"-i","A10":"timeout","Radware":" ","PaloAlto":"interval","Juniper SRX":"interval"},"value_key":"ping_interval"},
"TTL":{"option_key":{"default":"-t","A10":"ttl","Radware":"","PaloAlto":"ttl","Juniper SRX":"ttl"},"value_key":"ping_ttl"},
"Interface":{"option_key":{"default":"-I","A10":"","Radware":"","Citrix":"","PaloAlto":"","Juniper SRX":""},"value_key":"ping_interface"},
"Inet":{"option_key":{"default":"","Juniper SRX":"inet"}},
"Inet6":{"option_key":{"default":"","Juniper SRX":"inet6"}},
"wait_time":{"option_key":{"default":"","Juniper SRX":"wait"},"value_key":"ping_wait_time"},
},
"ping6_options":{
"Count":{"option_key":{"default":"-c","Radware":" "},"value_key":"ping_count"},
"Interval":{"option_key":{"default":"-i","Radware":" "},"value_key":"ping_interval"},
"TTL":{"option_key":{"default":"-t","Radware":""},"value_key":"ping_ttl"},
"Interface":{"option_key":{"default":"-I","Radware":"","Citrix":""},"value_key":"ping_interface"},
},
"ss_options":{
"All":{"option_key":{"default":"-a"}},
"Resolve host name":{"option_key":{"default":"-r"}},
"Listening":{"option_key":{"default":"-l"}},
"Info":{"option_key":{"default":"-i"}},
"Summary":{"option_key":{"default":"-s"}},
"Tcp":{"option_key":{"default":"-t"}},
},
"netstat_options":{
"All":{"option_key":{"default":"-a","PaloAlto":"all yes"}},
"Numeric address":{"option_key":{"default":"-n","PaloAlto":"numeric yes"}},
"Listening":{"option_key":{"default":"-l","PaloAlto":"listening yes"}},
"Programs":{"option_key":{"default":"-p","PaloAlto":"programs yes"}},
"Udp":{"option_key":{"default":"-u","PaloAlto":""}},
"Tcp":{"option_key":{"default":"-t","PaloAlto":""}},
"Unix":{"option_key":{"default":"-x","PaloAlto":""}},
},
"nslookup_options":{
"query":{"option_key":{"default":"-query="},"value_key":"nslookup_query_value"},
"type":{"option_key":{"default":"-type="},"value_key":"nslookup_type_value"},
"port":{"option_key":{"default":"-port="},"value_key":"nslookup_port_value"},
"timeout":{"option_key":{"default":"-timeout="},"value_key":"nslookup_timeout_value"},
},
"tracepath_options":{
"Do not look up host names":{"option_key":{"default":"-n"}},
"Set the initial packet length":{"option_key":{"default":"-l"}},
},
"netcat_options":{
"Do not do any DNS or service lookups":{"option_key":{"default":"-n"}},
"verbose":{"option_key":{"default":"-v"}},
"UDP":{"option_key":{"default":"-u"}},
"scan for listening daemons":{"option_key":{"default":"-z"}},
"listen for an incoming connection":{"option_key":{"default":"-l"}},
"source_ip_address":{"option_key":{"default":""}},
"timeout":{"option_key":{"default":"-w"},"value_key":"netcat_timeout"},
},
"traceroute_options":{
"Icmp echo for traceroute":{"option_key":{"default":"-I","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Tcp sync for traceroute":{"option_key":{"default":"-T","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Udp packet for tarceroute":{"option_key":{"default":"-U","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","Citrix":""}},
"Interface":{"option_key":{"default":"-i","A10":"","Juniper SRX":"interface","Radware":"","PaloAlto":"","Citrix":""},"value_key":"traceroute_interface"},
"TTL":{"option_key":{"default":"-m","A10":"","Juniper SRX":"ttl","Radware":"","PaloAlto":"","Citrix":"","CheckPoint":""},"value_key":"traceroute_ttl"},
"Do not resolve hostname":{"option_key":{"default":"-n","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"no-resolve yes"}},
"Wait time":{"option_key":{"default":"-w","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"wait","CheckPoint":""},"value_key":"traceroute_wait_time"},
"Number of probe packets per hop":{"option_key":{"default":"-q","A10":"","Juniper SRX":"","Radware":"","PaloAlto":"","CheckPoint":""},"value_key":"traceroute_probe_packets_per_hop"},
"Use Mgmt port":{"option_key":{"default":"","A10":"use-mgmt-port","Radware":"-mgmt"}},
"Gateway":{"option_key":{"default":"","Juniper SRX":"gateway","PaloAlto":"gateway"},"value_key":"traceroute_gateway"},
"Inet":{"option_key":{"default":"","Juniper SRX":"inet"},"value_key":"destination_device"},
"Inet6":{"option_key":{"default":"","Juniper SRX":"inet6"},"value_key":"destination_device"},
"Source":{"option_key":{"default":"","Juniper SRX":"source","PaloAlto":"source","CheckPoint":"-s"},"value_key":"traceroute_source"},
"max-hops":{"option_key":{"default":"","Radware":" "},"value_key":"traceroute_max_hops"},
"Delay":{"option_key":{"default":"","Radware":" "},"value_key":"traceroute_delay"},
"Pause":{"option_key":{"default":"","PaloAlto":"pause"},"value_key":"traceroute_pause"},
"Port":{"option_key":{"default":"","PaloAlto":"port","Citrix":"-p"},"value_key":"port"},
"Host":{"option_key":{"default":"","PaloAlto":"host"},"value_key":"destination_device"},
},
"traceroute6_options":{
"Do not resolve hostname":{"option_key":{"default":"-n"}},
"Wait time":{"option_key":{"default":"-w"},"value_key":"traceroute6_wait_time"},
"Number of probe packets per hop":{"option_key":{"default":"-q"},"value_key":"traceroute_probe_packets_per_hop"},
},
"snmpwalk_options":{
"community":{"option_key":{"default":"-c"},"value_key":"snmpwalk_community"},
"username":{"option_key":{"default":"-u"},"value_key":"snmpwalk_username"},
"authentication hash":{"option_key":{"default":"-a"},"value_key":"snmpwalk_hash"},
"authentication type":{"option_key":{"default":"-l"},"value_key":"snmpwalk_auth_type"},
"encryption":{"option_key":{"default":"-x"},"value_key":"snmpwalk_encryption"},
"auth phrase":{"option_key":{"default":"-A"},"value_key":"snmpwalk_auth_phrase"},
"privaphrase":{"option_key":{"default":"-X"},"value_key":"snmpwalk_priva_phrase"},
}
}
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for value in form_input:
        username, password, vendor_name, source_ip = get_device_details(value)
        if value['monitor_type'] == 'PING':
            command = ping(value,vendor_name,source_ip)
        elif value['monitor_type'] == 'NETCAT':
            command = netcat(value, vendor_name,source_ip)
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
        elif value['monitor_type'] == 'SNMPWALK':
            command = snmpwalk(value, vendor_name)
        else:
            command=''
        if (command != ''):
            if len(sys.argv)>1 and sys.argv[1]=='preview':
                print vendor_name,source_ip, ' ', command
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
"""