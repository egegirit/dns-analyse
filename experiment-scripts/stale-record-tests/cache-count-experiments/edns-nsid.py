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
resolver.payload = 4096

request = dns.message.make_query(domain, dns.rdatatype.A)
request.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, '')])
request.flags |= dns.flags.AD

responsez = dns.query.udp(request, name_server)

# print(f"responsez.answer: {responsez.answer}")
# print(f"responsez.sections: {responsez.sections}")
for a in responsez.answer:
    # print(f"Set:  {a.to_rdataset()}")
    print(f"TTL:  {a.to_rdataset().ttl}")

# if responsez is not None:
#     print(f"  New Answer:\n{responsez}")

for opt in responsez.options:
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

# print(f"answers.response:\n{answers.response}")

# print(f"aaaaaaaaa: {answers.response.answer}")
# for a in answers.response.answer:
#     print(f"Set:  {a.to_rdataset()}")
#     print(f"TTL:  {a.to_rdataset().ttl}")

# TODO
for opt in answers.response.options:
    if opt.otype == dns.edns.NSID:
        nsid = opt.data.decode("utf-8")
        print(f"NSID: {nsid}")
