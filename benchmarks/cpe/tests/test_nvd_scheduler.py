import unittest

from app.vulnerability.nvd.scheduler import NvdRequestScheduler


class SchedulerTests(unittest.TestCase):
    def test_shared_spacing_and_run_cap(self):
        now = [0.0]
        sleeps = []
        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay
        scheduler = NvdRequestScheduler(min_interval=0.7, max_requests=2,
                                        clock=lambda: now[0], sleeper=sleep)
        self.assertTrue(scheduler.acquire())
        self.assertTrue(scheduler.acquire())
        self.assertFalse(scheduler.acquire())
        self.assertEqual(sleeps, [0.7])
        self.assertEqual(scheduler.used, 2)


if __name__ == "__main__":
    unittest.main()
