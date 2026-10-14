"""Performance and resource benchmark for CyberPartha BOT v3."""
import resource, time, unittest
from core.scope.guard import ScopeGuard
from core.storage.db import StateDB
from intelligence.endpoints.normalizer import EndpointNormalizer

class TestPerformanceBenchmark(unittest.TestCase):
    def test_idle_and_processing_memory(self):
        start_time = time.time()
        scope = ScopeGuard(allowed_domains=["example.com", "target.org"])

        # Benchmark 1,000 endpoint normalizations
        for i in range(1000):
            url = f"https://api.example.com/v1/resource/{i}/item?token=secret_{i}&q=search"
            norm = EndpointNormalizer.normalize(url)
            self.assertTrue(scope.is_allowed_host(norm["host"]))

        elapsed = time.time() - start_time
        # Under 2 seconds for 1,000 normalizations
        self.assertLess(elapsed, 2.0)

        # Check maximum resident set size in MB
        usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        usage_mb = usage_kb / 1024.0
        # WSL/Linux tracks RSS in KB; ensure process stays lightweight (< 150MB)
        self.assertLess(usage_mb, 150.0)

if __name__ == '__main__':
    unittest.main()
