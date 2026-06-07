package main

// knownPorts maps well-known ports to a protocol label (parity with the Python reference).
var knownPorts = map[uint32]string{
	// Core Windows / network
	53: "DNS", 67: "DHCP Server", 68: "DHCP Client", 80: "HTTP", 88: "Kerberos",
	123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
	389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos Change/Set", 500: "ISAKMP (IPsec)",
	636: "LDAPS", 989: "FTPS", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
	// Email
	25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP Submission",
	// Remote access
	22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC",
	5938: "TeamViewer", 7070: "AnyDesk", 7071: "AnyDesk",
	// Windows-specific
	1025: "RPC Dynamic", 1026: "RPC Dynamic", 1027: "RPC Dynamic", 5357: "WS-Discovery",
	5358: "WS-Discovery", 5985: "WinRM HTTP", 5986: "WinRM HTTPS", 7680: "Windows Delivery Optimization",
	47001: "WinRM", 49664: "RPC Dynamic", 49665: "RPC Dynamic", 49666: "RPC Dynamic",
	49667: "RPC Dynamic", 49668: "RPC Dynamic", 49669: "RPC Dynamic",
	// Virtualization
	902: "VMware", 903: "VMware", 912: "VMware", 2179: "Hyper-V", 16509: "Libvirt",
	// Databases
	1433: "MSSQL", 1434: "MSSQL Browser", 1521: "Oracle DB", 2041: "Interbase/Firebird",
	2082: "cPanel", 2083: "cPanel SSL", 2086: "WHM", 2087: "WHM SSL", 2095: "Webmail",
	2096: "Webmail SSL", 2181: "Zookeeper", 2375: "Docker", 2376: "Docker TLS",
	2483: "Oracle DB SSL", 2484: "Oracle DB SSL", 27017: "MongoDB", 28015: "RethinkDB",
	3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 7474: "Neo4j", 9042: "Cassandra",
	// Web / proxies
	81: "HTTP Alt", 3000: "Dev Server", 3001: "Dev Server", 3128: "Squid Proxy",
	5000: "Flask / Dev", 5001: "Dev HTTPS", 7001: "WebLogic", 7002: "WebLogic SSL",
	8000: "HTTP Alt", 8008: "HTTP Alt", 8080: "HTTP Proxy / Alt", 8081: "HTTP Alt",
	8088: "HTTP Alt", 8089: "Splunk", 8181: "HTTP Alt", 8443: "HTTPS Alt", 8888: "Dev Server",
	9000: "SonarQube / Dev", 9090: "Prometheus / Web",
	// Monitoring
	9100: "Node Exporter", 9115: "Blackbox Exporter", 9125: "Netdata", 5601: "Kibana",
	// VPN
	1194: "OpenVPN", 1701: "L2TP", 1723: "PPTP", 4500: "IPsec NAT-T",
	// P2P
	6881: "BitTorrent", 6882: "BitTorrent", 6883: "BitTorrent", 6884: "BitTorrent",
	6885: "BitTorrent", 6886: "BitTorrent", 6887: "BitTorrent", 6888: "BitTorrent", 6889: "BitTorrent",
	// Multimedia
	1900: "UPnP", 2869: "UPnP", 8200: "DLNA", 32400: "Plex",
	// DevOps
	2377: "Docker Swarm", 6443: "Kubernetes API", 10250: "Kubelet", 10255: "Kubelet Readonly",
	// Others
	1812: "RADIUS", 1813: "RADIUS Accounting", 5060: "SIP", 5061: "SIP TLS",
	5222: "XMPP", 5269: "XMPP Server", 6667: "IRC", 6697: "IRC SSL",
	// More standard services
	853: "DNS over TLS", 5353: "mDNS", 5355: "LLMNR", 3478: "STUN", 5349: "STUN/TURN TLS",
	9418: "Git", 11211: "Memcached", 5672: "AMQP", 15672: "RabbitMQ Mgmt", 9092: "Kafka",
	5984: "CouchDB", 8086: "InfluxDB", 9200: "Elasticsearch", 3074: "Xbox Live",
	25565: "Minecraft", 27015: "Steam/Source", 51413: "Transmission",
}

// suspiciousPorts are default ports of well-known RATs / backdoors / worms / C2.
// A connection on one of these is a heuristic red flag and adds to the threat score.
var suspiciousPorts = map[uint32]string{
	1243:  "SubSeven (RAT)",
	1337:  "backdoor (leet)",
	2745:  "Bagle (worm)",
	3127:  "MyDoom (worm)",
	4444:  "Metasploit/Meterpreter",
	4445:  "Metasploit",
	5554:  "Sasser (worm)",
	6711:  "SubSeven (RAT)",
	6776:  "SubSeven (RAT)",
	9898:  "Dabber (worm)",
	12345: "NetBus (RAT)",
	12346: "NetBus (RAT)",
	20034: "NetBus 2 (RAT)",
	27374: "SubSeven (RAT)",
	31337: "Back Orifice (RAT)",
	54321: "Back Orifice 2000",
	65506: "PhatBot",
}
