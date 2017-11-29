import json
import re

from .crypto import CryptoTools


class ParameterType:
    def __init__(self, required=False, container_type=None, allowed_values=None):
        self.required = required
        self.container_type = container_type
        self.allowed_values = allowed_values

    def parse(self, parameter_name, parameter_value):
        if parameter_value is None:
            if self.required:
                raise AttributeError('Required parameter with name "%s" is not present' % parameter_name)
            else:
                parameter_value = ''
        if not self.container_type:
            return parameter_value

        if not isinstance(parameter_value, list):
            parameter_value = parameter_value.split()
        if self.allowed_values:
            for val in parameter_value:
                if val not in self.allowed_values:
                    raise AttributeError('Value "%s" is not allowed for parameter %s. Allowed values are %s'
                                         % (val, parameter_name,
                                            ', '.join(['"%s"' % x for x in sorted(self.allowed_values)])))
        if self.container_type is list:
            return parameter_value
        else:
            return self.container_type(parameter_value)

    def serialize(self, parameter_value):
        if self.container_type and parameter_value is not None:
            return list(parameter_value)
        else:
            return parameter_value

    def __eq__(self, other):
        if not isinstance(other, ParameterType):
            return False
        return self.required == other.required and \
               self.container_type == other.container_type and \
               self.allowed_values == other.allowed_values


class Parameters:
    """

    """

    """
    List of (param_name, ParameterType(...)) 
    """
    parameter_definitions = ()

    REQUIRED = ParameterType(required=True)
    OPTIONAL = ParameterType(required=False)
    ZLIB_DICT = b'openidhttp,,,,'

    def __init__(self, param_values):

        if param_values is not None:
            for parameter_name, parameter_definition in self.parameter_definitions:
                parsed_value = parameter_definition.parse(parameter_name, param_values.get(parameter_name, None))
                setattr(self, parameter_name, parsed_value)

    def to_dict(self):
        return {
            parameter_name: parameter_definition.serialize(getattr(self, parameter_name, None))
            for parameter_name, parameter_definition in self.parameter_definitions
        }

    def pack(self, encrypt=True, ttl=None, not_valid_before=None, key=None, prefix=b''):
        arr = []
        for d, dev in self.parameter_definitions:
            val = getattr(self, d)
            if isinstance(val, set) or isinstance(val, list) or isinstance(val, tuple):
                val = ' '.join(val)
            arr.append(str(val).replace('\\', '\\\\').replace(',', '\\,'))
        params = ','.join(arr)
        if not encrypt:
            return params
        return CryptoTools.encrypt(params.encode('utf-8'), ttl=ttl,
                                   not_valid_before=not_valid_before, key=key, prefix=prefix,
                                   zlib_dict=Parameters.ZLIB_DICT)

    @classmethod
    def unpack(cls, packed_data, decrypt=True, key=None, prefix=b''):
        if decrypt:
            params = CryptoTools.decrypt(packed_data, key=key, expected_prefix=prefix,
                                         zlib_dict=Parameters.ZLIB_DICT).decode('utf-8')
        else:
            params = packed_data
        params = re.split(r'(?<!\\),', params)
        param_dict = {}
        for d,p in zip(cls.parameter_definitions, params):
            val = p.replace('\\,', ',').replace('\\\\', '\\')
            param_dict[d[0]] = val

        return cls(param_dict)

    def __eq__(self, other):
        if not isinstance(other, Parameters):
            return False
        if self.parameter_definitions != other.parameter_definitions:
            return False
        for d, definition in self.parameter_definitions:
            if getattr(self, d) != getattr(other, d):
                return False
        return True

    def __str__(self):
        return json.dumps(self.to_dict(), sort_keys=True, default=lambda x: str(x))