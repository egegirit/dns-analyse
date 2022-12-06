import sys
import dns.resolver
import dns.reversename
from datetime import datetime
import time
import threading
import msvcrt

# DNS Open Resolver IP Addresses
resolver_ip_addresses = [
    # "94.140.14.14",  # AdGuard 1  -> 1
    # "94.140.14.15",  # AdGuard 2  (dns-family.adguard.com )
    # "94.140.14.140",
    # "185.228.168.168",  # CleanBrowsing 1  (family-filter-dns.cleanbrowsing.org )
    # "185.228.168.10",
    # "185.228.168.9",  # CleanBrowsing 2  (security-filter-dns.cleanbrowsing.org )
    # "1.1.1.1",  # Cloudflare 1     (one.one.one.one)
    # "1.1.1.2",
    # "1.1.1.3",
    # "216.146.35.35",  # Dyn 1  (resolver1.dyndnsinternetguide.com)
    # "8.8.8.8",  # Google 1  (dns.google )
    # "64.6.64.6",  # Neustar 1  (?)  ERROR
    # "156.154.70.2",  # Neustar 2  (?)  ERROR
    # "156.154.70.3",
    # "156.154.70.4",
    # "156.154.70.5",
    # "208.67.222.222",  # OpenDNS 1  (dns.opendns.com )
    # "208.67.222.2",  # OpenDNS 2  (sandbox.opendns.com )
    # "208.67.222.123",
    # "9.9.9.9",  # Quad9 1    (dns9.quad9.net )
    # "9.9.9.11",  # Quad9 2    (dns11.quad9.net)
    # "9.9.9.10",
    # "77.88.8.1",  # Yandex 1   (dns.yandex.ru)
    # "77.88.8.2",  # Yandex 2   (secondary.dns.yandex.ru)
    # "77.88.8.3"
    # "76.76.2.0",  # Control D
    # "76.76.10.0",
    # "76.76.2.1",
    # "76.76.2.2",
    # "76.76.2.3",
    "209.244.0.3",  # Level3_1
	"209.244.0.4",  # Level3_2

	"199.85.126.10",  # Norton_1
	"199.85.126.20",  # Norton_2
	"199.85.126.30"   # Norton_3
]

skip_to_next = False

file_name = "cache_count_logs_newIPs2.txt"
f = open(file_name, "a")

resolver = dns.resolver.Resolver()
# Set the timeout of the query
resolver.timeout = 10
resolver.lifetime = 10
query_name = "cachetest.cobalt106.messwithdns.com"
sleep_time = 1.1
max_ttl_of_record = 700
query_count = 60

print(f"Current time: {datetime.utcnow()}")
f.write(f"Current time: {datetime.utcnow()}\n")

print(f"Query count to send: {query_count}")
f.write(f"Query count to send: {query_count}\n")

print(f"sleep_time: {sleep_time}")
f.write(f"sleep_time: {sleep_time}\n")

print(f"query_name: {query_name}\n")
f.write(f"query_name: {query_name}\n\n")


def send_queries():
    global skip_to_next
    global resolver_ip_addresses
    for ip_addr in resolver_ip_addresses:

        ttl_list = []

        print(f"\n  Current Open Resolver: {ip_addr}")
        f.write(f"\n  Current Open Resolver: {ip_addr}\n")

        resolver.nameservers = [ip_addr]
        count_of_fresh_caches = 0
        current_max_ttl = 0
        count_of_max_ttl = 0

        for i in range(query_count):
            if skip_to_next:
                skip_to_next = False
                print(f"Skipping {ip_addr}")
                f.write(f"Skipping {ip_addr}\n")
                print(f"Estimated cache count of {ip_addr}: {count_of_fresh_caches}\n")
                f.write(f"Estimated cache count of {ip_addr}: {count_of_fresh_caches}\n\n")
                break

            try:
                answers = resolver.resolve(query_name, "A")
            except Exception:
                print(f"Exception or timeout occurred for {query_name} ")
                f.write(f"Exception or timeout occurred for {query_name} \n")
                answers = None

            try:
                # Show the DNS response and TTL time
                if answers is not None:
                    print(f"({i}): {answers.rrset.ttl}, ", end="")
                    f.write(f"({i}): {answers.rrset.ttl}, ")
                    ttl_list.append(int(answers.rrset.ttl))
                    if i == 0:
                        current_max_ttl = answers.rrset.ttl
                        print(f"First (Max?) TTL for {ip_addr} set to {current_max_ttl}, ", end="")
                        f.write(f"First (Max?) TTL for {ip_addr} set to {current_max_ttl}, ")
                        if int(answers.rrset.ttl) != max_ttl_of_record:
                            print(f"\n  Possible shared cache or reduced cache TTL for: {ip_addr} \n")
                            f.write(f"\n  Possible shared cache or reduced cache TTL for: {ip_addr} \n\n")
                    if int(answers.rrset.ttl) == max_ttl_of_record:
                        count_of_fresh_caches += 1
                        print(f"Cache count incremented: {count_of_fresh_caches}, ", end="")
                        f.write(f"Cache count incremented: {count_of_fresh_caches}, ")
                    if int(answers.rrset.ttl) == current_max_ttl:
                        count_of_max_ttl += 1
                        print(f"Observed Max TTL count incremented: {count_of_max_ttl}, ", end="")
                        f.write(f"Observed Max TTL count incremented: {count_of_max_ttl}, ")

            except Exception:
                print(f"Error when showing results of {query_name}")
                f.write(f"Error when showing results of {query_name}\n")
                # So that the order of the list doesn't get messed
                ttl_list.append(int(-99999))

            time.sleep(sleep_time)

        print(f"\nDone sending queries to {ip_addr}\n")
        f.write(f"\nDone sending queries to {ip_addr}\n\n")

        #temp_list = ttl_list.copy()
        #same_query = 0
        #calculated_ttls = []

        #for x in range(len(ttl_list)):
        #    if ttl_list[x] in calculated_ttls:
        #        continue

        #    found_same_query = False
        #    index_of_same_origin = 0
        #    for y in range(len(ttl_list)):
        #        if x == y:
        #            continue
        #        else:
        #            diff = abs(x - y)
        #            if diff * sleep_time == abs(ttl_list[x] - ttl_list[y]):
        #                found_same_query = True
        #                index_of_same_origin = x
        #                same_query += 1
        #                calculated_ttls.append(ttl_list[y])
        #                # TODO: when an item is deleted, all indexes after that item changes -> Fix?
        #                if y < len(temp_list) and ttl_list[y] in temp_list:
        #                    del temp_list[y]
        #                    # temp_list.remove(ttl_list[y])
        #    if found_same_query:
        #        calculated_ttls.append(ttl_list[index_of_same_origin])
        #        if index_of_same_origin < len(temp_list) and ttl_list[index_of_same_origin] in temp_list:
        #            temp_list.remove(ttl_list[index_of_same_origin])
        #            del temp_list[index_of_same_origin]

        #print(f"Unique Query TTLs: {temp_list}")
        #print(f"TTLs of Same Queries: {calculated_ttls}")
        #print(f"Same Query count: {same_query}")
        #print(f"Same_query - Total query = Cache count = {len(ttl_list) - same_query}")
        #f.write(f"Unique Query TTLs: {temp_list}\n")
        #f.write(f"TTLs of Same Queries: {calculated_ttls}\n")
        #f.write(f"Same Query count: {same_query}\n\n")
        #f.write(f"Same_query - Total query = Cache count = {len(ttl_list) - same_query}\n\n")

        print(f"\n  Observed Max TTL count of {ip_addr}: {count_of_max_ttl}")
        f.write(f"\n  Observed Max TTL count of {ip_addr}: {count_of_max_ttl}\n")
        print(f"  Estimated cache count of {ip_addr}: {count_of_fresh_caches}\n")
        f.write(f"  Estimated cache count of {ip_addr}: {count_of_fresh_caches}\n\n")

    f.write(f"\nEND\n")
    f.close()
    print(f"\nEND\n")
    sys.exit()

send_queries()
