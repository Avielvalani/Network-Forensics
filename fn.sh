#!/bin/bash

# Network forensics script

# Set variables
log_file="/var/log/syslog" # Change this to the location of your log file
start_time="$(date --date='1 hour ago' +'%b %d %H:%M:%S')" # Change this to the start time of your log analysis
end_time="$(date +'%b %d %H:%M:%S')" # Change this to the end time of your log analysis
ip="192.168.0.1" # Change this to the IP address you want to investigate

# Search for IP address in log file
grep "$start_time" "$log_file" "$end_time" | grep "$ip" > /tmp/$ip.log

# Analyze network traffic
tshark -r /tmp/$ip.log -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e http.request.uri -E header=y -E separator='|' > /tmp/$ip.csv

# Analyze HTTP traffic
cat /tmp/$ip.csv | grep "HTTP" > /tmp/$ip-http.csv

# Analyze HTTPS traffic
cat /tmp/$ip.csv | grep "HTTPS" > /tmp/$ip-https.csv

# Analyze DNS traffic
cat /tmp/$ip.csv | grep "DNS" > /tmp/$ip-dns.csv

# Analyze SMTP traffic
cat /tmp/$ip.csv | grep "SMTP" > /tmp/$ip-smtp.csv

# Analyze FTP traffic
cat /tmp/$ip.csv | grep "FTP" > /tmp/$ip-ftp.csv

# Analyze SSH traffic
cat /tmp/$ip.csv | grep "SSH" > /tmp/$ip-ssh.csv

# Analyze Telnet traffic
cat /tmp/$ip.csv | grep "Telnet" > /tmp/$ip-telnet.csv

# Analyze ICMP traffic
cat /tmp/$ip.csv | grep "ICMP" > /tmp/$ip-icmp.csv

# Analyze ARP traffic
cat /tmp/$ip.csv | grep "ARP" > /tmp/$ip-arp.csv

# Display summary of findings
echo "IP address: $ip"
echo "Total number of packets: $(cat /tmp/$ip.csv | wc -l)"
echo "Total number of HTTP packets: $(cat /tmp/$ip-http.csv | wc -l)"
echo "Total number of HTTPS packets: $(cat /tmp/$ip-https.csv | wc -l)"
echo "Total number of DNS packets: $(cat /tmp/$ip-dns.csv | wc -l)"
echo "Total number of SMTP packets: $(cat /tmp/$ip-smtp.csv | wc -l)"
echo "Total number of FTP packets: $(cat /tmp/$ip-ftp.csv | wc -l)"
echo "Total number of SSH packets: $(cat /tmp/$ip-ssh.csv | wc -l)"
echo "Total number of Telnet packets: $(cat /tmp/$ip-telnet.csv | wc -l)"
echo "Total number of ICMP packets: $(cat /tmp/$ip-icmp.csv | wc -l)"
echo "Total number of ARP packets: $(cat /tmp/$ip-arp.csv | wc -l)"

# Clean up temporary files
rm /tmp/$ip.log
rm /tmp/$ip.csv
rm /tmp/$ip-http.csv
rm /tmp/$ip-
