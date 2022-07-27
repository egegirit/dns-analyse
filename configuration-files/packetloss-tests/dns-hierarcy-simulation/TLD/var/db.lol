$TTL 3H
@	IN SOA	master.dns-tld.lol.	postmaster.dns-tld.lol. (
		2022072101
		1800
		900
		806400
		5400
		)

	IN	NS	ns1.dns-tld.lol.
	IN	NS	ns2.dns-tld.lol.

intranet.lol.	IN	NS	nameserver1.intranet.lol.
intranet.lol.	IN	NS	nameserver2.intranet.lol.

$ORIGIN lol.
ns1.dns-tld	IN	A	192.168.1.31
ns2.dns-tld	IN	A	192.168.1.31
nameserver1.intranet	IN	A	192.168.1.32
nameserver2.intranet	IN	A	192.168.1.32
