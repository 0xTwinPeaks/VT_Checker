# This will prompt the user to enter the hash to search for
$hash = Read-Host "Enter the hash to search for "
$VTapiKey = Read-Host "Enter the VirusTotal API key here "
clear-host

# Define the VirusTotal API endpoint
$VTapiUrl = "https://www.virustotal.com/api/v3/files/$hash"
$VTcontactedIPsUrl = "$VTapiUrl/contacted_ips"
$VTcontactedDomainsUrl = "$VTapiUrl/contacted_domains"

# Create headers for the API request
$headers = @{
    'x-apikey' = $VTapiKey
}

try {
    # Send a GET request to VirusTotal API
    $response = Invoke-RestMethod -Uri $VTapiUrl -Headers $headers
    
    #Convert epoch to local date
    $epochTimestamp = $response.data.attributes.last_analysis_date
    $localDateTime = (Get-Date "1970-01-01 00:00:00").AddSeconds($epochTimestamp)

    #This gathers network information from Virus Total
    $networkTraffic = $response.data.relationships.communicating_files.data        

    # Check if the request was successful
    if ($response.data.attributes.last_analysis_stats.harmless -lt 1) {
       
        # Banner
        Write-Host -ForegroundColor yellow "**************************************************"
        Write-Host -ForegroundColor yellow "***********     VIRUSTOTAL RESULTS     ***********"
        Write-Host -ForegroundColor yellow "**************************************************`r`n"
        
        # Hash
        Write-Host -ForegroundColor green "- Hash:"
        Write-Host "    *  $hash`r`n"
        Write-Host -ForegroundColor green "- Last Analysised by VT:"
        Write-Host "    *  Last Analysised By VT: $localDateTime`r`n"
       
        # How Many times its been uploaded from unique locations
        Write-Host -ForegroundColor green "- # of Unique Uploaded Sources:"
        Write-Host "    *  $($response.data.attributes.unique_sources)`r`n"
        
        # File Type Identification
        Write-Host -ForegroundColor green "`r`n- File Type: "            
        Write-Host "    *  $($response.data.attributes.type_description) `r`n"  
       
        #Known Names for Hash
        Write-Host -ForegroundColor green "- Known Names for Hash:"
        $NameVT = $response.data.attributes.names
        if ($NameVT) {
            foreach ($name in $NameVT) {
                Write-Host "    *  $name" }
        } else {
            Write-Host "    *  No Known Names for Hash."
        }
        
       
        # Security Vendors good or bad
        Write-Host -ForegroundColor green "`r`n- Security Vendor Identification List:"
        $VendorVT = $response.data.attributes.last_analysis_results.PSObject.Properties
        $anyVendorsIdentified = $false

        if ($VendorVT) {
            foreach ($vendor in $VendorVT) {
                $vendorName = $vendor.Name
                $vendorResult = $vendor.Value.result
                if ($null -ne $vendorResult -and $vendorResult -ne "") {
                    Write-Host "    *  $vendorName : $vendorResult"
                    $anyVendorsIdentified = $true
                }
            }
        }

        if (-not $anyVendorsIdentified) {
            Write-Host "    *  No Security Vendors Identified This Hash As Malicious."
        }

        
        # Network Traffic
        try {
            # Send a GET request to VirusTotal API for contacted IPs
            $ipResponse = Invoke-RestMethod -Uri $VTcontactedIPsUrl -Method GET -Headers $headers

            # Send a GET request to VirusTotal API for contacted domains
            $domainResponse = Invoke-RestMethod -Uri $VTcontactedDomainsUrl -Method GET -Headers $headers

            # Check if the request for IPs was successful
            if ($ipResponse.data) {

                # Contacted IP Addresses
                Write-Host -ForegroundColor green "`r`n- Contacted IP Addresses:"

                # Iterate through the data array for IPs
                foreach ($contactedIP in $ipResponse.data) {
                    $ip = $contactedIP.id
                    Write-Host "    *  $ip"
                }
            } else {
                Write-Host "No contacted IP addresses found for this hash."
            }

            # Check if the request for domains was successful
            if ($domainResponse.data) {
               
                # Contacted Domains
                Write-Host -ForegroundColor green "`r`n- Contacted Domains:"

                # Iterate through the data array for domains
                foreach ($contactedDomain in $domainResponse.data) {
                    $domain = $contactedDomain.id
                    Write-Host "    *  $domain"
                }
            } else {
                Write-Host "No contacted domains found for this hash."
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)"
        }


        # Mitre Attack
        Write-Host -ForegroundColor green "`r`n- MITRE Attack Matrix"
        $mitreUrl = "https://www.virustotal.com/api/v3/files/$hash/behaviour_mitre_trees"


        try {
            $mitreResponse = Invoke-RestMethod -Uri $mitreUrl -Headers $headers

            if ($mitreResponse.data) {
                $mitreData = $mitreResponse.data

                Write-Host " MITRE ATT&CK Information:"
                foreach ($key in $mitreData.PSObject.Properties) {
                    $tactic = $mitreData.$($key.Name)
                    Write-Host "  * Tactic: $($key.Name)"
                    Write-Host "    Techniques:"
                    foreach ($technique in $tactic.tactics.techniques) {
                        Write-Host "      - ID: $($technique.id)"
                        Write-Host "        Name: $($technique.name)"
                        Write-Host "        Link: $($technique.link)"
                    }
                }
            } else {
                Write-Host "No MITRE ATT&CK information available for this sample."
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)"
        }



        # Virus Total link    
        Write-Host -ForegroundColor Magenta "`r`n- VT Details URL: $($response.data.links.self)`r`n"
    } else {
        Write-Host "That hash was not discovered in VirusTotal."
    }

} catch {
    Write-Host "Error: $($_.Exception.Message)"
} 
pause