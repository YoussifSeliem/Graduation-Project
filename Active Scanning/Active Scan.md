## Active Scan Details 

- **Job 1:** Set up a Python script to perform active scanning using masscan.
- **Job 2:** Parse command-line arguments for interface and IP address.
- **Job 3:** Execute masscan with the provided interface and IP address.
- **Job 4:** Check if masscan found any open ports.

- **Job 5:** Parse masscan output to extract open port numbers.
- **Job 6:** Combine open port numbers into a comma-separated string.
- **Job 7:** Print the open port numbers.

- **Job 8:** Generate an nmap command based on the open port numbers and IP address.
- **Job 9:** Print the nmap command to be executed.

- **Job 10:** Execute the nmap command using subprocess.

- **Job 11:** Integrate the entire script to run in a single execution.

- **Job 12:** Test the script with different interfaces and IP addresses.
- **Job 13:** Handle edge cases and improve error handling in the script.
- **Job 14:** Document the script with usage instructions and examples

```
Usage: python scan_script.py <interface> <IP>
Usage: don't forget to run it as root/admin
```