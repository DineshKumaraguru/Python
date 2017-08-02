import sys
import paramiko
ssh = paramiko.SSHClient()
import json
import os
import time
import traceback
import base64
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import getpass
from suds.client import Client

def connect_remote(host,user,password):
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host,username = user,password = password,port = 22,timeout=120)
        return ssh
    except Exception as e:
        print((str(e)))

def get_dossier_key(license):
    file_name='/tmp/'+license+'_raw.txt'
    file_name_do='/tmp/'+license+'_dossier.txt'
    license_key = license.split('-')
    license_key = '-'+license_key[-1]
    fp = open(file_name,'r')
    output = fp.read()
    fp.close()
    output = output.split(license_key,1)[-1]
    output = output.split('[',1)[0]
    output = output.strip()
    output = output.replace("\\n","")
    fo = open(file_name_do,'w')
    fo.write(output)
    fo.close()
    return output


def get_license_from_F5_License_Server(dossier_string):
    eula_string = ""
    server_hostname = "activate.f5.com"
    email = "example.icontrol@f5.com"
    firstName = "example"
    lastName = "iControl"
    companyName = "F5"
    phone = "2062725555"
    jobTitle = "FSE"
    address = "111 EXAMPLE ICONTROL RD"
    city = "Seattle"
    stateProvince = "WA"
    postalCode = "98119"
    country = "United States"
    try:
        download_url = "https://" + server_hostname + "/license/services/urn:com.f5.license.v5b.ActivationService?wsdl"
        local_wsdl_file_name = str(server_hostname) + '-f5wsdl-w-https.xml'
        wsdl_data = []
        try:
            with open(local_wsdl_file_name, 'r') as fh_wsdl:
                wsdl_data = fh_wsdl.read()
        except Exception as e:
            pass

        if not wsdl_data:
            f5wsdl = urllib.request.urlopen(download_url)
            newlines = []
            for line in f5wsdl:
                newlines.append(line.decode().replace('http://' + server_hostname, 'https://' + server_hostname))
            fh_local = open(local_wsdl_file_name, 'w')
            fh_local.writelines(newlines)
            fh_local.close()
        url = "file:" + urllib.request.pathname2url(os.getcwd()) + "/" + local_wsdl_file_name
        client = Client(url)
        transaction = client.factory.create('ns0:LicenseTransaction')
        transaction = client.service.getLicense(
            dossier=dossier_string,
            eula=eula_string,
            email=email,
            firstName=firstName,
            lastName=lastName,
            companyName=companyName,
            phone=phone,
            jobTitle=jobTitle,
            address=address,
            city=city,
            stateProvince=stateProvince,
            postalCode=postalCode,
            country=country
        )
        eula_string = transaction.eula
        if transaction.state == "EULA_REQUIRED":
            transaction = client.service.getLicense(
                dossier=dossier_string,
                eula=eula_string,
                email=email,
                firstName=firstName,
                lastName=lastName,
                companyName=companyName,
                phone=phone,
                jobTitle=jobTitle,
                address=address,
                city=city,
                stateProvince=stateProvince,
                postalCode=postalCode,
                country=country,
            )
        if transaction.state == "LICENSE_RETURNED":
            license_string = transaction.license
        else:
            license_string = "License server returned error: Number:" + str(
                transaction.fault.faultNumber) + " Text: " + str(transaction.fault.faultText)
        return license_string
    except Exception as e:
        raise

def backup_old_license(ssh):
    stdin,stdout,stderr = ssh.exec_command('mv /config/bigip.license /config/bigip_old.license')


def apply_license(ssh,host,user,password):

    transport = paramiko.Transport((host, 22))
    transport.connect(username = user, password = password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put("/var/tmp/bigip.license","/config/bigip.license")
    transport.close()
    a,b,c = ssh.exec_command('reloadlic')

if __name__ == '__main__':
    user = sys.argv[1]
    paswd = sys.argv[2]
    IP = sys.argv[3]
    license_key = sys.argv[4]
    time.sleep(500)
    ssh = connect_remote(IP, user, paswd)
    mode = 'Internet'
    dossier_key = get_dossier_key(license_key)
    final_key = get_license_from_F5_License_Server(dossier_key)

    with open('/var/tmp/bigip.license','w+') as lic_file:
        lic_file.write(final_key)
        
    transport = paramiko.Transport((IP, 22))
    transport.connect(username = user, password = paswd)
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put("/var/tmp/bigip.license","/var/tmp/bigip.license")
    transport.close()

    comm_message = 'Unable to communicate with the Activation Server!'
    if final_key == None:
        sys.exit(comm_message)

    if "Error" in final_key:
        message = str(final_key.split(':')[-1].strip())
    else:
        #backup_old_license(ssh)
        #apply_license(ssh, IP, user, paswd)
        pass

    ssh.close()