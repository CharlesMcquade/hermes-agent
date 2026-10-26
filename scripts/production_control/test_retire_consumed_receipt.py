import unittest

import retire_consumed_receipt as rc


class InFlightTests(unittest.TestCase):
    def test_verified_round_is_retireable_after_settle_margin(self):
        r = {'status': 'verified', 'completed_at': 1000}
        self.assertTrue(rc.no_activation_in_flight(r, deadline=5000, now=1000 + rc.VERIFIED_SETTLE_SECONDS + 1))

    def test_fresh_verification_still_waits(self):
        r = {'status': 'verified', 'completed_at': 1000}
        self.assertFalse(rc.no_activation_in_flight(r, deadline=5000, now=1010))

    def test_rolled_back_waits_for_deadline(self):
        r = {'status': 'rolled_back', 'completed_at': 1000}
        self.assertFalse(rc.no_activation_in_flight(r, deadline=5000, now=4999))
        self.assertTrue(rc.no_activation_in_flight(r, deadline=5000, now=5001))

    def test_missing_completion_falls_back_to_deadline(self):
        self.assertFalse(rc.no_activation_in_flight({'status': 'verified'}, deadline=5000, now=4999))


if __name__ == '__main__':
    unittest.main()
