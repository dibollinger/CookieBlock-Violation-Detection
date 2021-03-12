#Author: Dino Bollinger
# LICENSE: MIT
"""
Very simple utility script to generate the difference between two tranco domain lists.

Used to remove duplicate domains.
"""

top1_million = set()
all_europe = set()


# Load Tranco 1 Million
count = 0

with open("Tranco_Worldwide_20_November_2020/top-1m.csv", 'r') as fd:
    for line in fd:
        top1_million.add(line.strip().split(sep=",")[1])
        count += 1

print(f"Num top 1 million: {count}")


# Load all paid domains present in Google Chrome survey, from the region Europe.
count = 0

with open("Tranco_Europe_22_November_2020/tranco_WNJ9.csv", 'r') as fd:
    for line in fd:
        all_europe.add(line.strip().split(sep=",")[1])
        count += 1

print(f"Num top europe: {count}")


# Compute domains that are not present in top 1 million
new_domains = sorted(all_europe - top1_million)
print(f"Num new URLs: {len(new_domains)}")

with open("./new_domains.txt", 'w') as fd:
    for n in new_domains:
        fd.write(n + "\n")
