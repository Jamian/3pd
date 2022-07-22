import os
import tempfile
import unittest

from pppd.pppd import _test

class TestPyPi(unittest.TestCase):

    def test_happy_pypi_file(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            requirements_file = os.path.join(tmpdirname, 'requirements.txt')
            with open(requirements_file, 'w') as f:
                f.write('3pd==1.0.0\ncrayons==1.0.0')
            
            _test(path=tmpdirname)

    def test_vulnerable_pypi_file(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            requirements_file = os.path.join(tmpdirname, 'requirements.txt')
            with open(requirements_file, 'w') as f:
                f.write('3pd\ncrayons==1.0.0')

            with self.assertRaises(SystemExit) as cm:
                _test(path=tmpdirname)
                self.assertEqual(cm.exception.code, 1)
