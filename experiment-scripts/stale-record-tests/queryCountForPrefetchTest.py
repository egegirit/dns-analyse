from random import randrange

cache_1 = 0
cache_2 = 0
cache_3 = 0
cache_4 = 0
cache_5 = 0


experiment_count = 100
query_count = 30
min_value = 1
max_value = 5

cache_miss = False
missed_experiments = []
miss_experiment_count = 0

for i in range(experiment_count):
    print(f"== Experiment {i+1} ==")

    for _ in range(query_count):
        generated_number = randrange(max_value) + min_value
        exec(f"cache_{generated_number} += 1")

    print(f"Cache 1: {cache_1}")
    print(f"Cache 2: {cache_2}")
    print(f"Cache 3: {cache_3}")
    print(f"Cache 4: {cache_4}")
    print(f"Cache 5: {cache_5}")

    if cache_1 == 0 or cache_2 == 0 or cache_3 == 0 or cache_4 == 0 or cache_5 == 0:
        cache_miss = True
        miss_experiment_count += 1
        missed_experiments.append(i)
        print(f"Cache missed! @@@@@@")

    # Reset experiment
    cache_1 = 0
    cache_2 = 0
    cache_3 = 0
    cache_4 = 0
    cache_5 = 0
    print(f"\n")

print(f"Cache miss: {cache_miss}")
print(f"Missed experiment index: {missed_experiments}")
print(f"Miss ratio: {miss_experiment_count}/{experiment_count}")
