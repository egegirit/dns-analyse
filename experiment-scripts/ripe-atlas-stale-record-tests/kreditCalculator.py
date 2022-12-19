from random import randrange


def calculate_prefetch_query_count(cache_count_of_resolver, desired_probability=0.95):
    query_count = 40
    min_value = 1
    max_value = cache_count_of_resolver

    # print(f"The resolver has {cache_count_of_resolver} caches")
    # print(f"We are sending {query_count} queries to the resolver")
    # print(f"Uniform distribution is assumed (Laplace)\n")

    cache_i_hit = 1 / cache_count_of_resolver
    cache_i_missed = 1 - (1 / cache_count_of_resolver)
    # print(f"Probability of Cache_i is hit with 1 query:     1/{cache_count_of_resolver} = {cache_i_hit}")
    # print(f"Probability of Cache_i is missed with 1 query:  1 - (1/{cache_count_of_resolver}) = {cache_i_missed}\n")

    cache_i_missed_total = ((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count
    cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)
    # print(
    #     f"Probability of Cache_i is missed with {query_count} query:  ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
    #     f"{query_count} = {cache_i_missed_total}")
    #
    # print(
    #     f"Probability of Cache_i is hit with {query_count} query:     1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
    #     f"{query_count} = {cache_i_hit_total}\n")

    while cache_i_hit_total < desired_probability:
        # print(f"Probability of total cache hit was not {desired_probability * 100}%")
        # print(f"  Incrementing query count from {query_count} to {query_count + 1}")
        query_count += 1
        cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)
        # print(
        #     f"  New probability of Cache hit with {query_count} query:  1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
        #     f"{query_count} = {cache_i_hit_total}\n")

    print(f"{desired_probability * 100}% cache hit probability is met with {query_count} queries.")
    return query_count


daily_kredit_limit = 1000000

query_cost_of_oneoff_experiment = 10

assumed_cache_count_of_probe_resolver = 18
desired_probability = 0.95

query_send_intervall_in_prefetch = 60
duration_of_prefetch_phase_in_secs = 3180
query_send_intervall_in_stale_in_secs = 120
duration_of_stale_phase_in_secs = 120 * 60
probe_count = 750

print(f"Daily kredit limit: {daily_kredit_limit}")
print(f"Query cost of one off experiment: {query_cost_of_oneoff_experiment}")
print(f"Assumed cache count of probe resolver: {assumed_cache_count_of_probe_resolver}")
print(f"All cache hit chance: {desired_probability}")
print(f"Query send intervall in stale phase in seconds: {query_send_intervall_in_stale_in_secs}")
print(f"Duration of stale phase in minutes: {duration_of_stale_phase_in_secs}")
print(f"Probe count: {probe_count}")

prefetch_query_count_for_one_probe = calculate_prefetch_query_count(assumed_cache_count_of_probe_resolver,
                                                                    desired_probability)
prefetching_phase_kredit_cost = prefetch_query_count_for_one_probe * probe_count * query_cost_of_oneoff_experiment
query_count_to_send_per_probe_in_stale_phase = duration_of_stale_phase_in_secs / query_send_intervall_in_stale_in_secs
kredit_cost_of_stale_phase_per_probe = query_count_to_send_per_probe_in_stale_phase * query_cost_of_oneoff_experiment
stale_phase_kredit_cost = kredit_cost_of_stale_phase_per_probe * probe_count
total_kredit_cost = prefetching_phase_kredit_cost + stale_phase_kredit_cost



def calculate_kredit_cost(kredit_limit, query_cost, prefetch_interval, prefetch_duration,
                          stale_interval, stale_duration, probe_count):
    prefetch_query_count_for_one_probe = prefetch_duration / prefetch_interval
    prefetching_phase_kredit_cost = prefetch_query_count_for_one_probe * probe_count * query_cost
    query_count_to_send_per_probe_in_stale_phase = stale_duration / stale_interval
    kredit_cost_of_stale_phase_per_probe = query_count_to_send_per_probe_in_stale_phase * query_cost
    stale_phase_kredit_cost = kredit_cost_of_stale_phase_per_probe * probe_count
    total_kredit_cost = prefetching_phase_kredit_cost + stale_phase_kredit_cost
    print(f"Prefetch query count for one probe: {prefetch_query_count_for_one_probe}")
    print(f"Prefetching phase kredit cost: {prefetching_phase_kredit_cost}")
    print(f"Query amount to send per probe in stale phase: {query_count_to_send_per_probe_in_stale_phase}")
    print(f"Kredit cost of stale phase per probe: {kredit_cost_of_stale_phase_per_probe}")
    print(f"Stale phase kredit cost: {stale_phase_kredit_cost}")
    print(f"Total kredit cost: {total_kredit_cost}")
    if total_kredit_cost > kredit_limit:
        print(f"Limit reached!")

calculate_kredit_cost(1000000, query_cost_of_oneoff_experiment, query_send_intervall_in_prefetch, duration_of_prefetch_phase_in_secs,
                          query_send_intervall_in_stale_in_secs, duration_of_stale_phase_in_secs, probe_count)

# print(f"Prefetch query count for one probe: {prefetch_query_count_for_one_probe}")
# print(f"Prefetching phase kredit cost: {prefetching_phase_kredit_cost}")
# print(f"Query amount to send per probe in stale phase: {query_count_to_send_per_probe_in_stale_phase}")
# print(f"Kredit cost of stale phase per probe: {kredit_cost_of_stale_phase_per_probe}")
# print(f"Stale phase kredit cost: {stale_phase_kredit_cost}")
# print(f"Total kredit cost: {total_kredit_cost}")
#
# if total_kredit_cost > daily_kredit_limit:
#     print(f"Limit reached!")

# With 500 Probes:
# Prefetching -> 350.000 Kredits
# 2 hours Stale Phase -> 600.000 Kredits
# Total -> 950.000 Kredits
#
# Find balance between probe count and stale phase duration
#
#
# Create separate A records for each probe with TTL 130 and IP 137.0.0.0
# Select 500 Probes
#
# Start packet capture
# Start prefetching phase, send 70 queries for each probe
# Wait for TTL
# Simulate 100 percent packetloss on auth server
# Change A record IPs from 137.0.0.0 to 137.1.1.1
# Start stale phase, for 2 hours, send a query every minute from all probes.
# End packet capture
