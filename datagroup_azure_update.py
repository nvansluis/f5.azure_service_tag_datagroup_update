#!/bin/python
# -*- coding: utf-8 -*-
# Azure IP Ranges and Service Tags update automation for BIG-IP
# Version: 1.3
# Last Modified: 11 Januari 2025
# Author: Niels van Sluis
#
# This script is based on work from Makoto Omura, F5 Networks Japan G.K,
# Regan Anderson, F5 Networks and Brett Smith, Principal Systems Engineer
#
# This Sample Software provided by the author is for illustrative
# purposes only which provides customers with programming information
# regarding the products. This software is supplied "AS IS" without any
# warranties and support.
#
# The author assumes no responsibility or liability for the use of the
# software, conveys no license or title under any patent, copyright, or
# mask work right to the product.
#
# The author reserves the right to make changes in the software without
# notification. The author also make no representation or warranty that
# such application will be suitable for the specified use without
# further testing or modification.
#-----------------------------------------------------------------------

import httplib
from urlparse import urlparse
import os
import re
import json
import commands
import datetime
import sys

#-----------------------------------------------------------------------
# User Options - Configure as desired
#-----------------------------------------------------------------------

# Microsoft Azure service tag (ENABLE ONLY ONE SERVICE TAG)
# See: https://docs.microsoft.com/en-us/azure/virtual-network/service-tags-overview#available-service-tags
service_tag = "AzureTrafficManager"

# URL that holds the dynamic location to the JSON file that contains the Azure IP Ranges and Service Tags.
url_azure_ip_ranges_and_service_tags = 'https://azure-servicetags.ipforward.nl/'

# Azure Record types to download & update
use_ipv4 = 1                            # IPv4 exclusions: 0=do not use, 1=use
use_ipv6 = 0                            # IPv6 exclusions: 0=do not use, 1=use

# Don't import these Azure IPs (IP must be exact match to IP as it exists in JSON record - IP/CIDR mask cannot be modified)
# Provide IPs (IPv4 and IPv6) in list format - ex. ["191.234.140.0/22", "2620:1ec:a92::152/128"]
noimport_ips = []

# Non-Azure IPs to add to IPV4 Exclude List
# Provide IPs in list format - ex. ["191.234.140.0/22", "131.253.33.215/32"]
additional_ipv4 = []

# Non-Azure IPs to add to IPV6 Exclude List
# Provide IPs in list format - ex. ["2603:1096:400::/40", "2620:1ec:a92::152/128"]
additional_ipv6 = []

# Action if Azure IP list is not updated
force_azure_record_refresh = 0           # 0=do not update, 1=update (for test/debug purpose)

# BIG-IP HA Configuration
device_group_name = "device-group1"     # Name of Sync-Failover Device Group.  Required for HA paired BIG-IP.
ha_config = 0                           # 0=stand alone, 1=HA paired

# Log configuration
log_level = 1                           # 0=none, 1=normal, 2=verbose

#-----------------------------------------------------------------------
# System Options - Modify only when necessary
#-----------------------------------------------------------------------

# BIG-IP Data Group names
ipv4_dg = "azure_ipv4_dg"
ipv6_dg = "azure_ipv6_dg"

# Working directory, file name for guid & version management
work_directory = "/shared/azure/"
file_ms_azure_version = "/shared/azure/azure_version.txt"
log_dest_file = "/var/log/azure_update"

#-----------------------------------------------------------------------
# Implementation - Please do not modify
#-----------------------------------------------------------------------
list_ipv4_to_exclude = []
list_ipv6_to_exclude = []

def log(lev, msg):
    if log_level >= lev:
        log_string = "{0:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()) + " " + msg + "\n"
        f = open(log_dest_file, "a")
        f.write(log_string)
        f.flush()
        f.close()
    return

def main():
    # -----------------------------------------------------------------------
    # Check if this BIG-IP is ACTIVE for the traffic group (= traffic_group_name)
    # -----------------------------------------------------------------------
    result = commands.getoutput("tmsh show /cm failover-status field-fmt")

    if ("status ACTIVE" in result) or (ha_config == 0):
        log(1, "This BIG-IP is standalone or HA ACTIVE. Initiating Azure update.")
    else:
        log(1, "This BIG-IP is HA STANDBY. Aborting Azure update.")
        sys.exit(0)

    #-----------------------------------------------------------------------
    # Get location of Azure IP Ranges and Service Tags JSON file
    #-----------------------------------------------------------------------

    parsed = urlparse(url_azure_ip_ranges_and_service_tags)
    conn = httplib.HTTPSConnection(parsed.netloc)
    conn.request('GET', parsed.path + '?' + parsed.query)
    res = conn.getresponse()

    if not res.status == 200:
        # MS Azure JSON download page request failed
        log(1, "Failed to fetch MS Azure JSON download page: " + url_azure_ip_ranges_and_service_tags)
        sys.exit(0)
    else:
        # MS Azure JSON download page request succeeded
        log(2, "Fetching MS Azure JSON download page was successful.")

    links = re.findall('(https://download.*?\.json)', res.read())

    json_url_download_location = links[0]

    #-----------------------------------------------------------------------
    # Azure IP Ranges and Service Tags version check
    #-----------------------------------------------------------------------

    # Read version of previously received record
    if os.path.isfile(file_ms_azure_version):
        f = open(file_ms_azure_version, "r")
        f_content = f.readline()
        f.close()
        # Check if the VERSION record format is valid
        if re.match('[0-9]+', f_content):
            ms_azure_version_previous = f_content
            log(2, "Valid previous VERSION found in " + file_ms_azure_version + ".")
        else:
            ms_azure_version_previous = "0"
            f = open(file_ms_azure_version, "w")
            f.write(ms_azure_version_previous)
            f.flush()
            f.close()
            log(1, "Valid previous VERSION was not found.  Wrote dummy value in " + file_ms_azure_version + ".")
    else:
        ms_azure_version_previous = "0"
        f = open(file_ms_azure_version, "w")
        f.write(ms_azure_version_previous)
        f.flush()
        f.close()
        log(1, "Valid previous VERSION was not found.  Wrote dummy value in " + file_ms_azure_version + ".")

    #-----------------------------------------------------------------------
    # Request Azure service tags list & put it in dictionary
    #-----------------------------------------------------------------------

    parsed = urlparse(json_url_download_location)
    conn = httplib.HTTPSConnection(parsed.netloc)
    conn.request('GET', parsed.path)
    res = conn.getresponse()

    if not res.status == 200:
        log(1, "Failed to fetch MS Azure JSON file: " + json_url_download_location)
        sys.exit(0)
    else:
        log(2, "Fetching MS Azure JSON file was successful.")
        dict_azure_all = json.loads(res.read())

    # Azure IP Ranges and Service Tags version check
    ms_azure_version_latest = str(dict_azure_all['changeNumber'])
    f = open(file_ms_azure_version, "w")
    f.write(ms_azure_version_latest)
    f.flush()
    f.close()

    log(2, "Previous VERSION is " + ms_azure_version_previous)
    log(2, "Latest VERSION is " + ms_azure_version_latest)

    if ms_azure_version_latest == ms_azure_version_previous and force_azure_record_refresh == 0:
        log(1, "You already have the latest MS Azure IP Address list: " + ms_azure_version_latest + ". Aborting operation.")
        sys.exit(0)

    for dict_azure_values in dict_azure_all['values']:
        if dict_azure_values['name'] == service_tag:
            dict_service_tag_properties = dict_azure_values['properties']
            list_ips = list(dict_service_tag_properties['addressPrefixes'])
            for ip in list_ips:
                if re.match('^.+:', ip):
                    list_ipv6_to_exclude.append(ip)
                else:
                    list_ipv4_to_exclude.append(ip)

    if use_ipv4:
        # Combine lists and remove duplicate IPv4 addresses
        ipv4_undup = list(set(list_ipv4_to_exclude + additional_ipv4))

        ## Remove set of excluded IPv4 addresses from the list of collected IPv4 addresses
        for x_ip in noimport_ips:
            ipv4_undup = [x for x in ipv4_undup if not x.endswith(x_ip)]

        log(1, "IPv4 host/net: " + str(len(ipv4_undup)))

    if use_ipv6:
        # Combine lists and duplicate IPv6 addresses
        ipv6_undup = list(set(list_ipv6_to_exclude + additional_ipv6))

        ## Remove set of excluded IPv6 addresses from the list of collected IPv6 addresses
        for x_ip in noimport_ips:
            ipv6_undup = [x for x in ipv6_undup if not x.endswith(x_ip)]

        log(1, "IPv6 host/net: " + str(len(ipv6_undup)))

    # -----------------------------------------------------------------------
    # IPv4 & IPv6 addresses formatted for TMSH
    # -----------------------------------------------------------------------

    if use_ipv4:
        # Initialize the IPv4 string
        ipv4_exclude_list = ""

        # Write IPv4 addresses to string
        for ip4 in (list(sorted(ipv4_undup))):
            ipv4_exclude_list = ipv4_exclude_list + ip4 + " { } "

    if use_ipv6:
        # Initialize the IPv6 string
        ipv6_exclude_list = ""

        # Write IPv6 addresses to string
        for ip6 in (list(sorted(ipv6_undup))):
            ipv6_exclude_list = ipv6_exclude_list + "{subnet " + ip6 + " } "

    # -----------------------------------------------------------------------
    # Load URL and/or IPv4 and/or IPv6 lists into data group
    # -----------------------------------------------------------------------

    if use_ipv4:
        result = commands.getoutput("tmsh create ltm data-group internal " + ipv4_dg + " type ip")
        result = commands.getoutput("tmsh modify /ltm data-group internal " + ipv4_dg + " records replace-all-with { " + ipv4_exclude_list + " }")
        log(2, "Updated datagroup " + ipv4_dg + " with latest IPv4 Azure address list.")

    if use_ipv6:
        result = commands.getoutput("tmsh create ltm data-group internal " + ipv6_dg + " type ip")
        result = commands.getoutput("tmsh modify /ltm data-group internal " + ipv6_dg + " records replace-all-with { " + ipv6_exclude_list + " }")
        log(2, "Updated datagroup " + ipv6_dg + " with latest IPv6 Azure address list.")

    #-----------------------------------------------------------------------
    # Save config
    #-----------------------------------------------------------------------
    log(1, "Saving BIG-IP Configuration.")
    result = commands.getoutput("tmsh save /sys config")
    log(2, result + "\n")

    #-----------------------------------------------------------------------
    # Initiate Config Sync: Device to Group
    #-----------------------------------------------------------------------

    if ha_config == 1:
        log(1, "Initiating Config-Sync.")
        result = commands.getoutput("tmsh run cm config-sync to-group " + device_group_name)
        log(2, result + "\n")

    log(1, "Completed Azure URL/IP update process.")

if __name__=='__main__':
    main()
