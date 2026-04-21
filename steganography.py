"""
If only knows only L, attacker can find P and M by:
  - Brute force by trying different starting offsets and cycling and fixed modes with given L
  - Statistical detection: look for LSB distribution imbalance, abnormal noise patterns
  - reverse it by reconstructing bit position, extracting modified bits, rebuild byte stream and decoding message
"""