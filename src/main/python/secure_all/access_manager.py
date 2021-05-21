"""Module AccessManager with AccessManager Class """

from secure_all.data.access_key import AccessKey
from secure_all.data.access_request import AccessRequest


class AccessManager:
    """AccessManager class, manages the access to a building implementing singleton """

    # pylint: disable=too-many-arguments,no-self-use,invalid-name, too-few-public-methods
    class __AccessManager:
        """Class for providing the methods for managing the access to a building"""

        @staticmethod
        def request_access_code(id_card, name_surname, access_type, email_address, days):
            """ this method give access to the building"""
            my_request = AccessRequest(id_card, name_surname, access_type, email_address, days)
            my_request.store_request()
            return my_request.access_code

        @staticmethod
        def get_access_key(keyfile):
            """Returns the access key for the access code & dni received in a json file"""
            my_key = AccessKey.create_key_from_file(keyfile)
            my_key.store_keys()
            return my_key.key

        @staticmethod
        def open_door(key):
            """Opens the door if the key is valid an it is not expired.
            If the door is opened, a JSON storage file keeps the access log"""
            open_key = AccessKey.create_key_from_id(key)
            if open_key.is_valid():
                open_key.store_access_log()
                return True
            return False

        @staticmethod
        def revoke_key(revoke_file):
            """Revokes the access for a key if its valid"""
            # create a key using the input file
            key = AccessKey.create_key_for_revoke(revoke_file)
            # check if the created key is valid
            if key.is_valid():
                # return the notification mails if the key is valid
                return str(key.notification_emails)
            return False

    __instance = None

    def __new__(cls):
        if not AccessManager.__instance:
            AccessManager.__instance = AccessManager.__AccessManager()
        return AccessManager.__instance
