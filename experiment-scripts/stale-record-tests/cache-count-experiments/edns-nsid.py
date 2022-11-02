import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.flags
import time

# DNS Open Resolver IP Addresses
resolver_ip_addresses = [

    "208.67.222.222",  # OpenDNS 1  (dns.opendns.com )
    "208.67.222.2",  # OpenDNS 2  (sandbox.opendns.com )

    "1.1.1.1",  # Cloudflare 1     (one.one.one.one)
    "1.0.0.1",  # Cloudflare 2     (1dot1dot1dot1.cloudflare-dns.com)

    "185.228.168.168",  # CleanBrowsing 1  (family-filter-dns.cleanbrowsing.org )
    "185.228.168.9",  # CleanBrowsing 2  (security-filter-dns.cleanbrowsing.org )

    "8.8.8.8",  # Google 1  (dns.google )
    "8.8.4.4",  # Google 2  (dns.google )

    "9.9.9.9",  # Quad9 1    (dns9.quad9.net )
    "9.9.9.11",  # Quad9 2    (dns11.quad9.net)
]

domain = "securitycharms.com"
send_count = 10
send_intervall = 1.3
expected_ttl_value = 300

nsids = set()
ttls = []
estimated_cache = 0

for current_ip in resolver_ip_addresses:
    print(f"----------------")
    print(f"IP: {current_ip}\n")
    # Reset
    nsids.clear()
    ttls.clear()
    estimated_cache = 0
    for i in range(send_count):
        request = dns.message.make_query(domain, dns.rdatatype.A)
        request.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, '')])
        request.flags |= dns.flags.AD

        responsez = dns.query.udp(request, current_ip)

        for a in responsez.answer:
            # print(f"Set:  {a.to_rdataset()}")
            ttl = int(a.to_rdataset().ttl)
            print(f"TTL:  {ttl}")
            ttls.append(ttl)
        if ttl == expected_ttl_value:
            estimated_cache += 1

        for opt in responsez.options:
            if opt.otype == dns.edns.NSID:
                nsid = opt.data.decode("utf-8")
                print(f"NSID: {nsid}\n")
                nsids.add(str(nsid))

        time.sleep(send_intervall)

    print(f"\nResult for: {current_ip}")
    print(f"Unique Identifier Count: {len(nsids)}")
    print(f"Estimated Cache Count: {estimated_cache}")
    print(f"TTL Values: {ttls}\n")

# print(f"responsez.answer: {responsez.answer}")
# print(f"responsez.sections: {responsez.sections}")


# if responsez is not None:
#     print(f"  New Answer:\n{responsez}")


# print(f"--------------------------")

# resolver = dns.resolver.Resolver()
# resolver.nameservers = [name_server]
# resolver.timeout = 10
# resolver.lifetime = 10
# resolver.edns = True
# resolver.payload = 4096

# try:
#     answers = resolver.resolve(domain, "A")
# except Exception:
#     print(f"Exception or timeout occurred")
#     answers = None

# try:
#     if answers is not None:
#         print(f"TTL of Answer: {answers.rrset.ttl}")
# except Exception:
#     print(f"Error when showing results")

# print(f"answers.response:\n{answers.response}")

# print(f"aaaaaaaaa: {answers.response.answer}")
# for a in answers.response.answer:
#     print(f"Set:  {a.to_rdataset()}")
#     print(f"TTL:  {a.to_rdataset().ttl}")

# TODO
# for opt in answers.response.options:
#    if opt.otype == dns.edns.NSID:
#        nsid = opt.data.decode("utf-8")
#        print(f"NSID: {nsid}")
