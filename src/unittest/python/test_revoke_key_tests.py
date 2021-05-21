"""Test for revoke_key method"""

import unittest
import csv
from secure_all import AccessManager, AccessManagementException, \
    JSON_FILES_PATH, KeysJsonStore, AccessKey, RequestJsonStore


class MyTestCase(unittest.TestCase):
    """ doc """

    # pylint: disable=no-member

    @classmethod
    def setUpClass(cls):
        """ inicializo el entorno de prueba """
        key_store = KeysJsonStore()
        key_store.empty_store()
        my_manager = AccessManager()

        # store in the json two access keys using valid jsons and the function get_access_key
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok2.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok3.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok4.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok5.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\key_ok6.json")
        # during testing, one of the previous will be deleted from the store, as it will be
        # used to test Revocation == "Final"

    def test_parametrized_cases_tests(self):
        """Parametrized cases read from testingCases_RF4.csv"""
        my_cases = JSON_FILES_PATH + "testingCases_RF4.csv"
        with open(my_cases, newline='', encoding='utf-8') as csv_file:
            # pylint: disable=no-member
            param_test_cases = csv.DictReader(csv_file, delimiter=';')
            my_code = AccessManager()
            keys_store = KeysJsonStore()
            for row in param_test_cases:
                file_name = JSON_FILES_PATH + row["FILE"]
                print("Param:" + row['ID TEST'] + row["VALID INVALID"])
                if row["VALID INVALID"] == "VALID":
                    valor = my_code.revoke_key(file_name)
                    self.assertEqual(row["EXPECTED RESULT"], valor)
                    print("el valor: " + valor)

                else:
                    with self.assertRaises(AccessManagementException) as c_m:
                        my_code.revoke_key(file_name)
                    self.assertEqual(c_m.exception.message, row["EXPECTED RESULT"])


if __name__ == '__main__':
    unittest.main()
