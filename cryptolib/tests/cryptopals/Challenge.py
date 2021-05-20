class Challenge():
    
    def __init__(self):
        self.name = ""

    solution = None

    def presolve(self):
        pass

    def solve(self):
        return 1

    def postsolve(self):
        """
        Sometimes solutions are non-deterministic so some work may need to be done to determine if the solution is correct.
        """
        pass

    def test_challenge(self):
        self.presolve()
        s = self.solve()
        self.postsolve()
        assert(self.solution == s)
        print(f"Passed test: {self.name}")