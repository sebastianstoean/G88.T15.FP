"""Implements the Access Log Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class AccessLogStore():
    """Extends JsonStore """

    class __AccessLogStore(JsonStore):
        # pylint: disable=invalid-name
        ID_FIELD = "_AccessLog__key"
        ACCESS_TIME = "_AccessLog__timestamp"

        _FILE_PATH = JSON_FILES_PATH + "storeLog.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Inserts an item to the access log json file"""
            self.load_store()
            self._data_list.append(item)
            self.save_store()

    __instance = None

    def __new__(cls):
        if not AccessLogStore.__instance:
            AccessLogStore.__instance = AccessLogStore.__AccessLogStore()
        return AccessLogStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
