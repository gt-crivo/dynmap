# Find Dynamic IP addresses

This python script can be used to find dynamic IP addresses from a collection of Shodan scans.

Run `python3 analyze_ips.py -h` to print a help menu with more detailed information.

This script supports only Shodan scans and can search IP addresses for modules https and ssh.

## The user can

- Add more modules by modifying the `initSupportedModules()` function
- Log every step of the analysis by using the `DEBUG` flag
- Save IP addresses found as .pickle files for later use

## Example usage

Given a directory `ufmg_ips` containing several Shodan scans as .json or .json.bz2 files

Run `python3 analyze_ips.py ufmg_ips/ https -f=output.log`

## Performance and Memory

This script requires a substantial amount of memory which scales linearly with the amount of unique IPs across scans, as well as the average amount of unique fingerprints per IP. As for the extraction process, several CPU cores are used at the same time to extract multiple files in parallel.

For example: to extract data from 92 .json.b2z files, 38 CPU cores and ~7 GB of memory were used. The whole process took 40 minutes from start to finish.

To help with the extraction process, a cache is built for the first run with a module. Subsequent runs with the same module will look for files in the cache folder.