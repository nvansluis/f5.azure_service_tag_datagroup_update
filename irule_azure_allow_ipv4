when FLOW_INIT {
    if { [class match [IP::remote_addr] equals /Common/azure_ipv4_dg] } {
        log local0. "Allow from Azure IP address: [IP::remote_addr]"
        ACL::action allow-final
    }
}
