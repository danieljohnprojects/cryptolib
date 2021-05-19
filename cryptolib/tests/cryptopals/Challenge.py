class Challenge():
    
    def __init__(self):
        self.name = ""

    solution = None

    def solve(self):
        return 1

    def test_challenge(self):
        assert(self.solution == self.solve())
        print(f"Passed test: {self.name}")