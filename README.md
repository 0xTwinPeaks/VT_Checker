The original version of the VirusTotal Quick Checker was a PowerShell script designed to interact with the VirusTotal API to retrieve and display detailed information about a file hash, including its analysis results, file type, known names, security vendor identifications, MITRE ATT&CK information, contacted IP addresses and domains. I basically needed a python version that could be used inside another script as module. Thus, I created the python version.

The script prompts the user to enter a file hash and VirusTotal api key, then it connects to the VirusTotal API and retrieves relevant data. It provides a clear and structured report.

To use the script, users need to provide their own VirusTotal API key for authentication: replace **$VTapiKey** variable with your own API key if you ddn't want to be prompted each time you run it. The script offers a thorough overview of file hash details in a convenient and readable format.

The following information is collected via the VirusTotal API: 

  **Hash**

  **Last Analysised by VT**

  **Number of Unique Uploaded Sources**

  **File Type**

  **Known Names for Hash**

  **Security Vendor Identification List**

  **Contacted IP Addresses**

  **Contacted Domains**

  **MITRE Attack Matrix**

  **VT Details URL**
