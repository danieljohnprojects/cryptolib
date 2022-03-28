# Pseudo-random functions

This module contains algorithms for generating pseudo-random streams of output.
Algorithms fall into two rough categories, pseudo-random number generators and pseudo-random byte generators.
The distinction between the two categories is of course somewhat arbitrary and algorithms from either category can be converted to the other rather trivially.
The algorithms have the same rough structure, taking a seed of some fixed bit-length on initialisation (appropriately padded with zeroes in the case of number generation).
