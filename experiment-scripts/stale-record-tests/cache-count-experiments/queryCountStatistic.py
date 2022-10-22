from random import randrange

cache_count_of_resolver = 18
query_count = 40
experiment_count = 100

caches = []
for i in range(cache_count_of_resolver):
    caches.append(0)

min_value = 1
max_value = len(caches)

print(f"The resolver has {len(caches)} caches")
print(f"We are sending {query_count} queries to the resolver")
print(f"Uniform distribution is assumed (Laplace)\n")

print(f"Probability of Cache_i is hit with 1 query:     1/{len(caches)} = {1/len(caches)}")
print(f"Probability of Cache_i is missed with 1 query:  1 - (1/{len(caches)}) = {1 - (1/len(caches))}\n")

print(f"Probability of Cache_i is missed with {query_count} query:  ({len(caches)}-1/{cache_count_of_resolver})^"
      f"{query_count} = {((len(caches) - 1) / cache_count_of_resolver)**query_count}")

print(f"Probability of Cache_i is hit with {query_count} query:     1 - ({len(caches)}-1/{cache_count_of_resolver})^"
      f"{query_count} = {1 - (((len(caches) - 1) / cache_count_of_resolver)**query_count)}")
