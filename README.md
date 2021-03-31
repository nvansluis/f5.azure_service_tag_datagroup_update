# Dynamicly update data groups with Azure IP Ranges for given Service Tag

This script fetches the Azure IP Ranges (IPv4 and/or IPv6) JSON file from Microsoft's Azure IP Ranges and Service Tags page and dynamically creates and updates IPv4 and IPv6 data groups. These datagroups can be used to allow access from Azure. If the script is running on an HA pair of BIG-IPs then the script will also initiate a ConfigSync to push the updated configuration from the active BIG-IP to the standby BIG-IP.

By default the script is using the 'AzureTrafficManagement' service tag, which will fill the IPv4 data group with Azure IP Ranges from which Azure Traffic Management will perform the health tests.

## Script Requirements
* TMOS 12.1.0 or higher
* BIG-IP must be capable of resolving internet DNS names (ex. via DNS Lookup Server configuration)
* Administrative rights on the BIG-IP(s)
* Bash shell access on the BIG-IP(s)

## Implementation

1. Modify the "User Options" in the script to match your environment and requirements
2. SSH to the standalone or active BIG-IP
3. Change to the bash shell  
  `bash`
4. Create the directory the script will reside in. The default directory is /shared/azure/.  
  `mkdir /shared/azure`  
  *Note: If not creating the directory as it is above, ensure you update the variables under **System Options** with the correct path.*
5. Upload or create the script (datagroup_azure_update.py) in the working directory (default path: /shared/azure/)
6. Manually run the script  
  `python /shared/azure/datagroup_azure_update.py`
7. Confirm the script ran without error by displaying the log file (default path: /var/log/azure_update):  
  `cat /var/log/azure_update`
8. If this is an HA pair, repeat steps 2 - 7. Note, it is normal for the Standby BIG-IP to log the following message when the update script is run:  
 `This BIG-IP is HA STANDBY. Aborting Azure update.`
9. On the Active BIG-IP, create an iCall script. This script executes the datagroup_azure_update.py script when it is called by an iCall handler, which we will create in the next step. Ensure the correct path to the script is referenced, in case defaults were not used.  
 `tmsh create sys icall script azure_update_script definition { catch { exec python /shared/azure/datagroup_azure_update.py } }`
10. On the Active BIG-IP, create an iCall handler. This handler will run at the configured interval and will execute the iCall script, which in turn executes the datagroup_azure_update.py Python script. A few examples of periodic handlers are given, choose (and adapt) the one that suits your needs best.  

    Run once every 60 minutes (3600 seconds), starting now:  
    `tmsh create sys icall handler periodic azure_update_handler script azure_update_script interval 3600`  
 
    Run once every 24 hours (86400 seconds), starting on March 20, 2020 at 03:00:  
    `tmsh create sys icall handler periodic azure_update_handler script azure_update_script interval 86400 first-occurrence 2020-03-20:03:00:00`

11. On the Active BIG-IP, save changes:  
  `tmsh save sys config`
12. Synchronize changes from the Active BIG-IP to the Standby BIG-IP

This concludes the steps required to install this script.
