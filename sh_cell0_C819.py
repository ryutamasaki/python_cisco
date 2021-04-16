#!/usr/bin/env python
'''
    File name: template_cisco_csv.py
    Author: Minh-Chau Bui
    Python Version: 3.9.1
    
    Usage: Admin CMD -> python <template_cisco_csv>.py -c <ip_list>.csv
           <ip_list>.csv CSV header row has to be 'device_ip'
'''

import getpass
import csv
import netmiko
import paramiko
from argparse import ArgumentParser

def main():
    # Argument Parser
    parser = ArgumentParser(description='Arguments for running template_cisco_csv.py')
    parser.add_argument('-c', '--csv', required=True, action='store', help='Location of IP list as CSV')
    args = parser.parse_args()

    # SSH Credentials
    ssh_username = input("SSH username: ")
    ssh_password = getpass.getpass('SSH Password: ')
    
    # Creation of target file used for output
    target_filename = "sh_cell0_C819.csv"
    cliOutput = open(target_filename, 'w')
    # CSV header
    cliOutput.write("Router;Telefonnummer;Channel Number;Current Band;Tech Selected;RSSI;RSRP;RSRQ;SNR;Modem Firmware")
    cliOutput.close()

    with open(args.csv, "r") as file:
        reader = csv.DictReader(file)
        
        # For loop going through every line in <ip_list>.csv
        for device_row in reader:
            try:
                cliOutput = open(target_filename, 'a+')

                ssh_session = netmiko.ConnectHandler(device_type='cisco_ios', ip=device_row['device_ip'],
                username=ssh_username, password=ssh_password)

                find_hostname = ssh_session.find_prompt()
                hostname = find_hostname.replace("#","")

                # show Command used for required data
                cmd = "show cellular 0 all"
                channel = ""
                out = ssh_session.send_command_expect(cmd)
                # For loop going through every line of the command output
                for line in out.split("\n"):
                    if "IDentity" in line:
                        sim = line.strip().removeprefix('IDentity Number (MSISDN) = ')
                    if "Channel Number" in line:
                        channel = line.strip().removeprefix('Channel Number = ')
                    if "Current Band" in line:
                        band = line.strip().removeprefix('Current Band = ')
                    if "LTE Technology Selected" in line:
                        lte = line.strip().removeprefix('LTE Technology Selected = ')
                    if "RSSI" in line:
                        rssi_filter = line.strip()
                        if "RSCP" in rssi_filter:
                            rssi = line.strip().removeprefix('Current RSSI(RSCP) = ')
                        else:
                            rssi = line.strip().removeprefix('Current RSSI = ')
                    if "RSRP" in line:
                        rsrp = line.strip().removeprefix('Current RSRP = ')
                    if "RSRQ" in line:
                        rsrq = line.strip().removeprefix('Current RSRQ = ')
                    if "SNR" in line:
                        snr = line.strip().removeprefix('Current SNR = ')
                    if "Firmware Version" in line:
                        firmware = line.strip().removeprefix('Modem Firmware Version = ')
                # Writing the row into the target_filename
                cliOutput.write("\n{0};{1};{2};{3};{4};{5};{6};{7};{8};{9}".format(hostname,sim,channel,band,lte,rssi,rsrp,rsrq,snr,firmware))
                
                # CLI success output
                print ("Auf dem Router {0}, mit der IP {1}, wurde der Befehl erfolgreich ausgeführt.".format(hostname,device_row['device_ip']))

            except (netmiko.ssh_exception.NetMikoTimeoutException,
            netmiko.ssh_exception.NetMikoAuthenticationException,
            paramiko.ssh_exception.SSHException) as s_error:
                print(s_error)
        cliOutput.close()

if __name__ == "__main__":
    main()
