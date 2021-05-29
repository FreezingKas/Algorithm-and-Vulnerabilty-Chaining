import json
import unittest

from Vulnerability import Vulnerability
from cvss_calculator import calculate_basescore
from utils import args_formatter
from variables import parameters


class MyTestCase(unittest.TestCase):
    def test_json(self):
        """
        Test with all the CVE in the json files
        :return:
        """

        with open('nvdcve-1.1-2021.json', encoding='utf8') as file:
            data = json.load(file)

        for param in data["CVE_Items"]:
            # Some CVE has not parameters for BaseScore calculation (194 exactly), so i can't use them
            if "baseMetricV3" not in param["impact"]:
                continue

            # we wil store parameters in this tab
            list_param = []

            # we juste take the parameters for the calculation
            for key, value in param["impact"]["baseMetricV3"]["cvssV3"].items():
                if key.lower() in map(str.lower, parameters):
                    list_param.append(value.lower())

            # get basescore from JSON and we calculate it
            baseScore = param["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            v = Vulnerability(list_param)
            res = v.get_basescore()

            print(param["cve"]["CVE_data_meta"]["ID"]
                  + " --> BaseScore JSON : " + str(baseScore)
                  + " BaseScore Programme : " + str(res))

            # test
            self.assertEqual(res, baseScore, f"Should be {baseScore}")

    def test_with_list(self):
        """
        Little test because we have to test the function with a list args not only the object method
        :return:
        """
        test_list = [["local", "low", "low", "none", "unchanged", "low", "low", "none"],
                     ["network", "low", "none", "none", "unchanged", "low", "low", "none"],
                     ["local", "low", "high", "none", "unchanged", "high", "high", "high"]]

        basescore = [4.4, 6.5, 6.7]

        for idx, vuln in enumerate(test_list):
            args_formatter(vuln)
            res = calculate_basescore(vuln)
            self.assertEqual(res, basescore[idx], f"Should be {basescore[idx]}")

    def test_chain(self):
        """
        Test the vulnerability chaining
        :return:
        """
        pass


if __name__ == '__main__':
    unittest.main()
