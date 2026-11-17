from algorithms import kmp_search,rabin_karp_search
import time
import random
import string
import matplotlib.pyplot as plt
from statistics import median

def generate_text(size):
    return ''.join(random.choices(string.ascii_lowercase, k=size))

def measure_time(algorithm, text, pattern, repeats=7):
    times = []
    algorithm(text, pattern)
    for _ in range(repeats):
        start = time.perf_counter()
        algorithm(text, pattern)
        end = time.perf_counter()
        times.append(end - start)
    return median(times)
 
input_sizes = [1000, 5000, 10000, 20000, 40000, 80000, 120000, 160000]
pattern = "fraud_pattern_not_present_2026"

kmp_times = []
rk_times = []

for size in input_sizes:
    print(f"Testing input size: {size}")
    text = generate_text(size)
    kmp_times.append(measure_time(kmp_search, text, pattern))
    rk_times.append(measure_time(rabin_karp_search, text, pattern))

kmp_ms = [t * 1000 for t in kmp_times]
rk_ms = [t * 1000 for t in rk_times]

plt.figure(figsize=(10, 6))
plt.plot(input_sizes, kmp_ms, marker='o', label='KMP')
plt.plot(input_sizes, rk_ms, marker='s', label='Rabin-Karp')
plt.xlabel("Input Text Size (characters)")
plt.ylabel("Execution Time (milliseconds)")
plt.title("KMP vs Rabin-Karp: Execution Time Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("execution_time_comparison.png", dpi=300)
plt.show()

kmp_normalized = [(t / n) * 1000000 for t, n in zip(kmp_times, input_sizes)]
rk_normalized = [(t / n) * 1000000 for t, n in zip(rk_times, input_sizes)]

plt.figure(figsize=(10, 6))
plt.plot(input_sizes, kmp_normalized, marker='o', label='KMP')
plt.plot(input_sizes, rk_normalized, marker='s', label='Rabin-Karp')
plt.xlabel("Input Text Size (characters)")
plt.ylabel("Execution Time per Character (microseconds)")
plt.title("Normalized Execution Time Comparison")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("normalized_execution_time.png", dpi=300)
plt.show()

print("\nExecution Time Results")
print("-" * 55)
print(f"{'Input Size':<20}{'KMP (ms)':<15}{'Rabin-Karp (ms)'}")
print("-" * 55)

for i in range(len(input_sizes)):
    print(f"{input_sizes[i]:<20}{kmp_ms[i]:<15.5f}{rk_ms[i]:.5f}")
    
    