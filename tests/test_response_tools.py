import unittest

from src.response_tools import ResponseSimulator


class ResponseToolTests(unittest.TestCase):
    def test_response_is_simulated_and_requires_approval(self):
        proposal = ResponseSimulator().isolate_host("ws-01")["data"][0]
        self.assertTrue(proposal["simulated"])
        self.assertTrue(proposal["requires_human_approval"])
