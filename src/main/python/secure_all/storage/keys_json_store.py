"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class KeysJsonStore():
    """Extends JsonStore """

    class __KeysJsonStore(JsonStore):
        # pylint: disable=invalid-name
        ID_FIELD = "_AccessKey__key"
        ACCESS_CODE = "_AccessKey__access_code"
        DNI = "_AccessKey__dni"
        MAIL_LIST = "_AccessKey__notification_emails"
        REVOCATION = "_AccessKey__revoked"
        INVALID_ITEM = "Invalid item to be stored as a key"
        KEY_ALREADY_STORED = "key already found in storeRequest"

        _FILE_PATH = JSON_FILES_PATH + "storeKeys.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            # pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_key import AccessKey

            if not isinstance(item, AccessKey):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.key) is None:
                raise AccessManagementException(self.KEY_ALREADY_STORED)

            return super().add_item(item)

        def add_revoke(self, item):
            """add an item to the store without the __dict__ extension"""
            self.load_store()
            self._data_list.append(item)
            self.save_store()

        def change_revoke(self, item):
            """Change the revoked attribute of the input item inside the storage"""
            self.load_store()
            stored_item = self.find_item(item[self.ID_FIELD])
            if not stored_item:
                raise AccessManagementException("key not found in json")
            self.delete_item(stored_item)
            stored_item[self.REVOCATION] = True
            self.add_revoke(stored_item)
            self.save_store()

    __instance = None

    def __new__(cls):
        if not KeysJsonStore.__instance:
            KeysJsonStore.__instance = KeysJsonStore.__KeysJsonStore()
        return KeysJsonStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
