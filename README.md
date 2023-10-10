# VirusTotal Quick Checker
This PowerShell script is designed to interact with the VirusTotal API to retrieve and display detailed information about a file hash, including its analysis results, file type, known names, security vendor identifications, MITRE ATT&CK information, and contacted IP addresses and domains. The script prompts the user to enter a file hash, connects to the VirusTotal API using an API key, and retrieves relevant data. It provides a clear and structured report with color-coded sections for easy reading. Additionally, it includes links to the VirusTotal website for more detailed information.

The script serves as a valuable tool for security analysts and researchers to quickly access comprehensive data about a specific file hash, aiding in the identification and assessment of potential threats.

To use the script, users need to provide their own VirusTotal API key for authentication: replace $VTapiKey value with your own API key. The script offers a thorough overview of file hash details in a convenient and readable format.

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
