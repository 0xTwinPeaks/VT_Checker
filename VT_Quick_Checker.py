import os
import sys
import requests
import datetime
import shutil
import hashlib
import re

VTapiKey = input("Enter your VirusTotal API key here: ")

# Output directory for result files
outputDirectory = "Results"
vt_results_folder = f"{outputDirectory}/Discovered_In_Virus_Total"
benign_folder = f"{vt_results_folder}/Benign"
malicious_folder = f"{vt_results_folder}/Malicious"
Not_Found = f"{outputDirectory}/Not_Found_In_Virus_Total"
os.makedirs(outputDirectory, exist_ok=True)
os.makedirs(vt_results_folder, exist_ok=True)
os.makedirs(benign_folder, exist_ok=True)
os.makedirs(malicious_folder, exist_ok=True)
os.makedirs(Not_Found, exist_ok=True)

# Command-line argument check
if len(sys.argv) == 2:
    selectedFile = sys.argv[1]
elif len(sys.argv) == 1:
    selectedFile = input("Enter the hash to perform a VT lookup, a file path to hash a file first then perform the VT lookup, or use this syntax 'file:<filepath>' to perform a VT lookup on hashes in a newline separted text file: ").strip()
else:
    print("Usage: python VT_Quick_Checker.py <hash_string, file_path, or 'file:<filename>'>")
    sys.exit(1)

# A file to store the report prior to moving to malicious/benign folder
result_file = (f"{outputDirectory}/{selectedFile}.txt")

# Function to clear the screen based on the operating system
def clear_screen():
    if os.name == 'nt':  # Windows
        try: 
            os.system('cls')
        except:  # Linux and others
            os.system('clear')
        finally:
            pass

# Function to hash a file
def hash_file(selectedFile):
    sha256_hash = hashlib.sha256()
    with open(selectedFile, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to check if a file contains valid hash values
def is_valid_hash_file(selectedFile):
    with open(selectedFile, 'r') as file:
        for line in file:
            hash_type = detect_hash_type(line.strip())
            if hash_type is None:
                return False
    return True

# Function to determine the hash type
def detect_hash_type(selectedFile):
    hash_str = selectedFile.lower()
    if re.match(r'^[0-9a-f]{32}$', hash_str):
        return "MD5"
    elif re.match(r'^[0-9a-f]{64}$', hash_str):
        return "SHA256"
    elif re.match(r'^[0-9a-f]{128}$', hash_str):
        return "SHA512"
    elif re.match(r'^[0-9a-f]{40}$', hash_str):
        return "SHA1"
    elif re.match(r'^[0-9a-f]{64}$', hash_str):
        return "AuthentiHash"
    elif re.match(r'^[0-9a-fA-F]{32}$', hash_str):
        return "ImpHash"
    else:
        return None

# Define the VirusTotal API endpoint
def vt_api_request(selectedFile, VTapiKey):
    VTapiUrl = f"https://www.virustotal.com/api/v3/files/{selectedFile}"
    mitre_url = f"https://www.virustotal.com/api/v3/files/{selectedFile}/behaviour_mitre_trees"
    VTcontactedIPsUrl = f"{VTapiUrl}/contacted_ips"
    VTcontactedDomainsUrl = f"{VTapiUrl}/contacted_domains"

    # Make API request to VirusTotal
    headers = {'x-apikey': VTapiKey}
    response = requests.get(VTapiUrl, headers=headers)
    mitre_response = requests.get(mitre_url, headers=headers)
    contactedIps = requests.get(VTcontactedIPsUrl, headers=headers)
    contactedDomains = requests.get(VTcontactedDomainsUrl, headers=headers)

    return response, mitre_response, contactedIps, contactedDomains

# Function to analyze a hash using VirusTotal
def analyze_hash(selectedFile, VTapiKey):
    response, mitre_response, contactedIps, contactedDomains = vt_api_request(selectedFile, VTapiKey)
    output = []

    if response.status_code == 200: 
        # Convert epoch to local date
        localDateTime = datetime.datetime.utcfromtimestamp(response.json()['data']['attributes']['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S')

        # Check if the file is considered malicious
        stats = response.json()['data']['attributes']['last_analysis_stats']
        is_malicious = stats['harmless'] < 1 and stats['malicious'] > 0

        # Collect information
        output.append("**************************************************")
        output.append("***********     VIRUSTOTAL RESULTS     ***********")
        output.append("**************************************************")
        output.append(f"\n- Hash:\n    *  {selectedFile}\n")
        output.append(f"- Last Analysed by VT:\n    *  Last Analysed By VT: {localDateTime}\n")
        output.append(f"- # of Unique Uploaded Sources:\n    *  {response.json()['data']['attributes']['unique_sources']}")
        output.append(f"\n- File Type:\n    *  {response.json()['data']['attributes']['type_description']}\n")
        if is_malicious is True: 
            output.append(f"This file has flagged on rules written by security product vendors.")
        else:
            output.append(f"This file has not flagged on rules written by security product vendors.")

        # Names for Hash
        output.append("- Names for sample:")
        name_vt = response.json()['data']['attributes'].get('names', [])
        for name in name_vt:
            output.append(f"    *  {name}")
        if not name_vt:
            output.append("    *  No names for sample.")

        # Security Vendor Identification List
        output.append("\n- Security Vendor Identification List:")
        vendor_vt = response.json()['data']['attributes']['last_analysis_results']
        for vendor_name, vendor_result in vendor_vt.items():
            result = vendor_result.get('result')
            if result is not None and result != "":
                output.append(f"    *  {vendor_name} : {result}")

        # Calling functions to add Ips and Domains
        output.append("\n- Network Activity")
        output.append("\n- IP addresses observed:")

        if contactedDomains is not None:
            # Loops to add ips contacted by the sample
            ips_data = contactedIps.json()
            ips_raw = ips_data.get("data", {})
            ip_addresses = [item["id"] for item in ips_raw]
            
            # Print the extracted IP addresses
            for ip_address in ip_addresses:
                output.append(ip_address)
            output.append("\n")

        output.append("\n- Domains observed")

        if contactedDomains is not None:
            # Loops to add domains contacted by the sample
            domains_data = contactedDomains.json()
            domains_raw = domains_data.get("data", {})
            domains = [item["id"] for item in domains_raw]
            
            # Print the extracted domains
            for domain in domains:
                output.append(domain)
            output.append("\n")
        else:
            output.append("\n No network activity found for this sample.")

        # Loop to add tactics, techniques, and signatures
        output.append("\n- Mitre ATT&CK Information")

        mitre_data = mitre_response.json()
        sandbox_data = mitre_data.get("data", {})

        if sandbox_data:
            for sandbox_name, sandbox_info in sandbox_data.items():
                output.append(f"Tool: {sandbox_name}")
                tactics = sandbox_info.get("tactics", [])
                for tactic in tactics:
                    tactic_name = tactic.get("name", "")
                    output.append(f"Tactic: {tactic_name}")
                    techniques = tactic.get("techniques", [])
                    for technique in techniques:
                        technique_id = technique.get("id", "")
                        technique_name = technique.get("name", "")
                        technique_link = technique.get("link", "")
                        output.append(f"  Technique:")
                        output.append(f"    - ID: {technique_id}")
                        output.append(f"      Name: {technique_name}")
                        output.append(f"      Link: {technique_link}")
        else:
            output.append("No Sandbox data found for this sample.")

        # Write the combined output to the result file
        with open(result_file, 'w') as result_file_opened:
            result_file_opened.write('\n'.join(output))
        move_files_based_on_content(result_file)

    else:
        output.append(f"That sample was not discovered in VirusTotal.")

        # Write the combined output to the result file
        with open(result_file, 'w') as result_file_opened:
            result_file_opened.write('\n'.join(output))
        move_files_based_on_content(result_file)
    
# Move all created files under the correct folder
def move_files_based_on_content(result_file):
    
    noSeVeId = f"This file has flagged on rules written by security product vendors."
    noFoInVT = f"That sample was not discovered in VirusTotal."

    with open(result_file, 'r') as file:
        # Iterate through files in the source folder
        source_file_path = result_file
        file_content = file.read()
        
        # Extract the filename from the result_file path
        selectedFilename = os.path.basename(result_file)
        
        if noSeVeId in file_content:
            # Move the file to the malicious folder
            destination_path = f"{malicious_folder}/{selectedFilename}"

        elif noFoInVT in file_content:
            destination_path = f"{Not_Found}/{selectedFilename}"
            
        else:
            # Move the file to the benign folder
            destination_path = f"{benign_folder}/{selectedFilename}"

    # Close the file explicitly before moving it
    shutil.move(source_file_path, destination_path)

# Main loop
hash_type = detect_hash_type(selectedFile)

#Initialize counters
createdFileCount = 0
invalidHashes = 0

if hash_type is not None:
    if hash_type == "MD5" or hash_type == "SHA256" or hash_type == "SHA512" or hash_type == "SHA1" or hash_type == "SSDEEP" or hash_type == "AuthentiHash" or hash_type == "ImpHash":
        # Handle the case where selectedFile is a hash
        analyze_hash(selectedFile, VTapiKey)

    elif selectedFile.startswith("file:"):
        # Handle the case where selectedFile is a hash file
        hash_file_path = selectedFile[len("file:"):].strip()
        if os.path.isfile(hash_file_path):
            # Open the file and read it line by line
            with open(hash_file_path, 'r') as file:

                for line in file:
                    # Remove leading and trailing whitespace from the line
                    line = line.strip()

                    # Process the line using the detect_hash_type function
                    if detect_hash_type(line):
                        print(f"Valid hash: {line}")
                        analyze_hash(line, VTapiKey)
                        createdFileCount += 1
                    else:
                        invalidHashes += 1

                    print("Total Results:", createdFileCount)
                    print("Total Invalid Results:", invalidHashes)

    elif os.path.exists(selectedFile):
        # Handle the case where selectedFile is a file path to a sample to be hashed
        hash = hash_file(selectedFile)
        new_hash = hash_type(selectedFile)
        if new_hash == "SHA256":
            analyze_hash(hash, VTapiKey)
        else:
            print("Unable to generate a valid SHA256 hash for file prior to VT lookup.")

        # Clear the screen (you can replace this with your desired screen clearing method)
        clear_screen()

else:
    print("Invalid hash format. Please provide a valid MD5, SHA256, SHA512, SHA1, AuthentiHash, or ImpHash.")