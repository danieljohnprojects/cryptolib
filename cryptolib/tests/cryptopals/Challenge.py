import unittest

class Challenge(unittest.TestCase):
    solution = None

    def solve(self):
        return 1

    def test_challenge(self):
        self.assertEqual(self.solution, self.solve())