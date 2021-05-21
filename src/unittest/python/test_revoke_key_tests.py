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
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        requests_store.empty_store()
        keys_store.empty_store()

        my_manager = AccessManager()
        # store in the json the access keys needed for the tests to execute
        # for this, we have created a total of 6 new keys and stored them in the json
        my_manager.request_access_code("05270358T", "Pedro Martin",
                                       "Resident", "uc3m@gmail.com", 0)

        my_manager.request_access_code("53935158C", "Marta Lopez",
                                       "Guest", "uc3m@gmail.com", 5)

        my_manager.request_access_code("87654123L", "Maria Montero",
                                       "Guest", "maria@uc3m.es", 15)

        my_manager.request_access_code("49717014F", "Marta Benito",
                                       "Guest", "marta@uc3m.es", 15)

        my_manager.request_access_code("07049955H", "Sebastian Stoean",
                                       "Guest", "sebas@uc3m.es", 15)

        my_manager.get_access_key(JSON_FILES_PATH + r"\rk_key_ok.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\rk_key_ok2.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\rk_key_ok3.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\rk_key_ok4.json")
        my_manager.get_access_key(JSON_FILES_PATH + r"\rk_key_ok5.json")
        # during testing, one of the previous will be deleted from the store, as it will be
        # used to test Revocation == "Final" and 3 more will be changed to revoke == True

        my_manager.request_access_code("68026939T", "Juan Perez",
                                       "Guest", "expired@gmail.com", 2)
        my_key_expirated = AccessKey.create_key_from_file(JSON_FILES_PATH +
                                                          "key_ok_testing_expired.json")
        # We manipulate the expiration date to obtain an expired AccessKey
        my_key_expirated.expiration_date = 0
        my_key_expirated.store_keys()

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
