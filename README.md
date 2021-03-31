# Dynamicly update data groups with Azure IP Ranges for given Service Tag

This script fetches the Azure IP Ranges (IPv4 and/or IPv6) JSON file from Microsoft's Azure IP Ranges and Service Tags page and dynamically creates and updates IPv4 and IPv6 data groups. These datagroups can be used to allow access from Azure. If the script is running on an HA pair of BIG-IPs then the script will also initiate a ConfigSync to push the updated configuration from the active BIG-IP to the standby BIG-IP.

## Script Requirements
TMOS 12.1.0 or higher
BIG-IP must be capable of resolving internet DNS names (ex. via DNS Lookup Server configuration)
BIG-IP must be able to reach endpoints.office.com via TCP 443 (via Management or TMM interface)
Administrative rights on the BIG-IP(s)
Bash shell access on the BIG-IP(s)
