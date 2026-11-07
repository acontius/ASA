import unittest
from benchmarks.cpe.src.runner import serialize_result

class SerializationTests(unittest.TestCase):
    def test_jsonl_serialization_is_stable(self):
        row={"z":1,"unicode":"محلی","a":{"b":2}}
        self.assertEqual(serialize_result(row),serialize_result(row))
        self.assertEqual(serialize_result(row),'{"a":{"b":2},"unicode":"محلی","z":1}')

if __name__=="__main__": unittest.main()
