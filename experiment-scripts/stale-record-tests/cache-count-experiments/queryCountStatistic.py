from random import randrange

cache_count_of_resolver = 18
query_count = 40
desired_probability = 0.90

min_value = 1
max_value = cache_count_of_resolver

print(f"The resolver has {cache_count_of_resolver} caches")
print(f"We are sending {query_count} queries to the resolver")
print(f"Uniform distribution is assumed (Laplace)\n")

cache_i_hit = 1/cache_count_of_resolver
cache_i_missed = 1 - (1/cache_count_of_resolver)
print(f"Probability of Cache_i is hit with 1 query:     1/{cache_count_of_resolver} = {cache_i_hit}")
print(f"Probability of Cache_i is missed with 1 query:  1 - (1/{cache_count_of_resolver}) = {cache_i_missed}\n")

cache_i_missed_total = ((cache_count_of_resolver - 1) / cache_count_of_resolver)**query_count
cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver)**query_count)
print(f"Probability of Cache_i is missed with {query_count} query:  ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
      f"{query_count} = {cache_i_missed_total}")

print(f"Probability of Cache_i is hit with {query_count} query:     1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
      f"{query_count} = {cache_i_hit_total}\n")

while cache_i_hit_total < desired_probability:
    print(f"Probability of total cache hit was not {desired_probability*100}%")
    print(f"  Incrementing query count from {query_count} to {query_count + 1}")
    query_count += 1
    cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)
    print(
        f"  New probability of Cache hit with {query_count} query:  1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
        f"{query_count} = {cache_i_hit_total}\n")

print(f"{desired_probability*100}% Probability is met with {query_count} queries.")
