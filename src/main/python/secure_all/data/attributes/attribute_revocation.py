"""Attribute class for validating the AccessType"""
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.attributes.attribute import Attribute

class Revocation(Attribute):
    """Class that includes the validation rules for access_type
    including the logic for validatin the days"""

    ACCESS_TYPE_GUEST = "Guest"
    ACCESS_TYPE_RESIDENT = "Resident"

    def __init__( self,attr_value ):
        self._validation_pattern = r'(Temporal|Final)'
        self._error_message = "revocation invalid"
        self._attr_value = self._validate(attr_value)
