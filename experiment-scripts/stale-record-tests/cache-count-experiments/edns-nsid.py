import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.flags


domain = "google.com"
name_server = "1.1.1.1"


resolver = dns.resolver.Resolver()
# Set the resolver IP Address
resolver.nameservers = [name_server]
# Set the timeout of the query
resolver.timeout = 10
resolver.lifetime = 10
resolver.edns = True


request = dns.message.make_query(domain, dns.rdatatype.A)
request.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, '')])
request.flags |= dns.flags.AD

response = dns.query.udp(request, name_server)

if response is not None:
    print(f"  New Answer:\n{response}")

for opt in response.options:
    if opt.otype == dns.edns.NSID:
        nsid = opt.data.decode("utf-8")
        print(f"\nNSID: {nsid}")


print(f"--------------------------")
try:
    answers = resolver.resolve(domain, "A")
except Exception:
    print(f"Exception or timeout occurred")
    answers = None

try:
    if answers is not None:
        print(f"TTL of Answer: {answers.rrset.ttl}")
except Exception:
    print(f"Error when showing results")
for opt in response.options:
    if opt.otype == dns.edns.NSID:
        nsid = opt.data.decode("utf-8")
        print(f"NSID: {nsid}")
