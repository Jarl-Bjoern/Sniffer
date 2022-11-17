#!/usr/bin/env python3
#-*- coding: utf-8 -*-
# Rainer Herold
# Version 0.1 11.10.2022

# Libraries
from os import makedirs
from os.path import exists
from scapy.all import *
from subprocess import getoutput
from sys import argv
from time import sleep
from threading import Thread

# Arrays
Array_Sniff = []

# Dict
Dict_NIC = {}

# Functions
def Initialien():
    print ("----------------------------------------")
    print ("|                Sniffer                |")
    print ("|              Version 0.1              |")
    print ("|             Rainer Herold             |")
    print ("----------------------------------------\n")

def Sniff_Packets(pkt):
        #def Filter(x):
        #    if (':' in str(x)):
        #        if (str(x).split(':')[0] in Dict_NIC): return f'Interface: {Dict_NIC[IP[5]]} -> '
        #    else:
        #        if (str(IP[5]) in Dict_NIC): return f'Interface: {Dict_NIC[IP[5]]} -> '

        Filter = str(pkt.summary())
        IP = Filter.split(' ')
        Result = ''
        if ('.' in str(IP[5]) and '.' in str(IP[7])):
            if (':' in str(IP[5])):
                if (str(IP[5]).split(':')[0] in Dict_NIC): Result = f'Interface: {Dict_NIC[IP[5]]} -> '
            else:
                if (str(IP[5]) in Dict_NIC): Result = f'Interface: {Dict_NIC[IP[5]]} -> '

            if (':' in str(IP[7])):
                if (str(IP[7]).split(':')[0] in Dict_NIC): Result = f'Interface: {Dict_NIC[IP[7]]} -> '
            else:
                if (str(IP[7]) in Dict_NIC): Result = f'Interface: {Dict_NIC[IP[7]]} -> '

            if (exists("/opt/Tools/sniffer-result.txt")):
                with open('/opt/Tools/sniffer-result.txt', 'r') as f:
                    Array_Sniff = f.read().splitlines()

            Result += f'Source: {IP[5]} -> Destination: {IP[7]}'
            if (Result not in Array_Sniff):
                    Array_Sniff.append(Result)
                    if (not exists("/opt/Tools")): makedirs("/opt/Tools")
                    with open('/opt/Tools/sniffer-result.txt', 'a') as f: f.write(f'{Result}\n')
                    print (Result)
        else: print(Filter)

def main():
        NICS = getoutput ('ifconfig | grep -v "LOOPBACK" | grep "flags" | cut -d " " -f1').splitlines()
        IP = getoutput('ifconfig | grep inet | grep -v -E "127.0.0.1|inet6" | cut -d " " -f10').splitlines()
        for i in range(0, len(IP)):
                Dict_NIC[f'{str(IP[i])}'] = NICS[i]

        def Thread_Start(x):
                sniff(iface=x, count=1, store=0, prn=Sniff_Packets, filter="ip")

        while True:
                for NIC in Dict_NIC.values():
                        t1 = Thread(target=Thread_Start, args=[str(NIC)], daemon=True)
                        t1.start()
                        sleep(0.15)
                sleep(2.5)

# Main
if __name__ == '__main__':
        Initialien(), main()
