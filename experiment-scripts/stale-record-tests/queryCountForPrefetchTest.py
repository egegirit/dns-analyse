from random import randrange

caches = []
max_cache_count = 10
for i in range(max_cache_count):
    caches.append(0)

experiment_count = 100
query_count = 50
min_value = 1
max_value = len(caches)

print(f"Cache Length: {len(caches)}\n")

cache_miss = False
missed_experiments = []
miss_experiment_count = 0

for i in range(experiment_count):
    cache_miss = False
    print(f"== Experiment {i+1} ==")

    for _ in range(query_count):
        generated_number = randrange(max_value) + min_value
        caches[generated_number-1] += 1

    index = 0
    for x in caches:
        print(f"Cache {index+1}: {caches[index]}")
        if caches[index] == 0:
            cache_miss = True
        index += 1

    if cache_miss:
        miss_experiment_count += 1
        missed_experiments.append(i)
        print(f"Cache missed! @@@@@@")

    # Reset
    index = 0
    for x in caches:
        caches[index] = 0
        index += 1

    print(f"\n")

print(f"Cache miss: {cache_miss}")
print(f"Missed experiment index: {missed_experiments}")
print(f"Miss ratio: {miss_experiment_count}/{experiment_count}")