$TTL 3600
@	IN	SOA	master.intranet.lol.	postmaster.intranet.lol. (
			2022072203
			1800
			900
			806400
			5400
			)
		NS	nameserver1.intranet.lol.
		NS	nameserver2.intranet.lol.

$ORIGIN intranet.lol.
nameserver1	IN	A	192.168.1.32
nameserver2	IN	A	192.168.1.32
sarah		IN	A	192.168.10.100
www		IN	A	10.10.100.23
