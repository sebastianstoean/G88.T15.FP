"""Attribute class for validating the AccessType"""
from secure_all.data.attributes.attribute import Attribute


class Revocation(Attribute):
    """Class that includes the validation rules for access_type
    including the logic for validatin the days"""
    # pylint: disable=too-few-public-methods
    ACCESS_TYPE_GUEST = "Guest"
    ACCESS_TYPE_RESIDENT = "Resident"

    def __init__(self, attr_value):
        self._validation_pattern = r'(Temporal|Final)'
        self._error_message = "revocation invalid"
        self._attr_value = self._validate(attr_value)
