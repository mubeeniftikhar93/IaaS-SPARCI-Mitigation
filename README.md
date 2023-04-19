# IaaS-SPARCI Mitigation for Dos and ssh

### For Ubuntu/Debian
```
git clone https://github.com/mubeeniftikhar93/IaaS-SPARCI-Mitigation.git
sudo chmod +x dosandssh.sh
sudo ./dosandssh.sh
```

After running the script, IPTables custom configuration was applied. If IPTables is not installed on your OS, it will be installed when running the script.

/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
The "INVALID" state in the connection tracking system means that the packet does not match any known connection or is otherwise invalid. This can happen due to various reasons such as incorrect sequence numbers, checksum errors, or other protocol violations.
/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
this rule is blocking any TCP traffic that is not part of an established connection (i.e., it is not a SYN packet or it is not already being tracked by the connection tracking system), which can help prevent certain types of network attacks.
/sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
The rule is dropping incoming TCP traffic that is in the "NEW" state and has a TCP maximum segment size (MSS) outside of the range of 536 to 65535 bytes
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
The rule is dropping incoming TCP traffic with no TCP flags set (i.e., the "NONE" flag), which is a common flag combination used in certain types of network attacks, such as a NULL scan. This is done to prevent these types of attacks and improve the overall security of the network.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
Command drops incoming TCP packets with both the FIN and SYN flags set, which is an invalid combination that is often used in TCP scans or SYN flood attacks.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
Command drops incoming TCP packets with both the SYN and RST flags set, which is another invalid combination that can be used in certain types of attacks, such as a TCP session hijacking attack.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
Command drops incoming TCP packets with both the SYN and FIN flags set, which is another invalid combination that can be used in certain types of network attacks, such as a TCP session reset attack.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
Command drops incoming TCP packets with both the FIN and RST flags set, which is also an invalid combination that can be used in certain types of network attacks
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
command drops incoming TCP packets with only the FIN flag set and the ACK flag not set, which is an invalid combination that can be used in certain types of network attacks, such as a TCP FIN scan.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
Command drops incoming TCP packets with only the URG flag set and the ACK flag not set, which is another invalid combination that can be used in certain types of network attacks, such as a TCP urgent data attack.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
Command drops incoming TCP packets with only the FIN flag set and the ACK flag set, which is another invalid combination that can be used in certain types of network attacks, such as a TCP session hijacking attack.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
Command drops incoming TCP packets with only the PSH flag set and the ACK flag not set, which is another invalid combination that can be used in certain types of network attacks, such as a TCP Push attack.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
 command drops incoming TCP packets with all six TCP flags (FIN, SYN, RST, PSH, ACK, URG) set, which is an invalid combination that can be used in certain types of network attacks, such as a TCP XMAS scan.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
The second command drops incoming TCP packets with no TCP flags set, which is another invalid combination that can be used in certain types of network attacks, such as a TCP NULL scan.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
drops incoming TCP packets with the FIN, PSH, and URG flags set and all other flags cleared. This combination of flags is used in certain types of network attacks, such as a TCP FIN-PSH-URG scan, and dropping these packets can help improve network security.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
drops incoming TCP packets with the SYN, FIN, PSH, and URG flags set and all other flags cleared. This combination of flags is another invalid combination that can be used in certain types of network attacks, such as a TCP SYN-FIN-PSH-URG scan.
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
drops incoming TCP packets with all five TCP flags (SYN, RST, ACK, FIN, URG) set. This combination of flags is an invalid combination that can be used in certain types of network attacks, such as a TCP Christmas Tree scan.
/sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
/sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP
This can be used to block ICMP requests and responses and can help prevent certain types of network attacks or probes
/sbin/iptables -t mangle -A PREROUTING -f -j DROP
Command is an iptables rule that drops all IP packets with the "fragment" flag set in the mangle table's PREROUTING chain. This can be used to prevent certain types of network attacks that use fragmented packets to evade network security measures or to overload network resources  However, it may also interfere with legitimate network traffic that uses fragmentation for valid reasons
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 200 -j REJECT --reject-with tcp-reset
This command adds a rule to the INPUT chain of the iptables firewall, which applies to incoming TCP traffic. It uses the "connlimit" extension to limit the number of connections per source IP address, and if the limit of 200 connections is exceeded, it rejects the connection attempt with a TCP reset packet. This can be used as a measure to prevent DDoS attacks or to limit the impact of abusive clients on a server.
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
This command adds a rule to the INPUT chain of the iptables firewall. The rule matches TCP packets with the RST flag set, and uses the "limit" module to limit the rate of matching packets to 2 per second, with a burst of 2 packets allowed. If the limit is exceeded, the packets are dropped. If the limit is not exceeded, the packets are accepted.
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
This iptables command adds a rule to the INPUT chain to drop all incoming TCP packets that have the RST flag set, which is commonly used to terminate a TCP connection. This can be useful to prevent certain types of attacks, such as TCP RST attacks.
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
This iptables command adds a rule to the INPUT chain of the filter table to accept new incoming TCP connections, but limits the rate of such connections to 60 per second, with a burst limit of 20. This is done using the conntrack and limit modules in iptables.
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 100 --hitcount 5 -j DROP
/sbin/iptables -N port-scanning
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
/sbin/iptables -A port-scanning -j DROP
service iptables restar
 

## References
<a id="1">[1]</a> 
https://codeberg.org/KasperIreland/ddos-protection-script/src/branch/main
