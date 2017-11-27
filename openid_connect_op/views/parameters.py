from openid_connect_op.utils.params import Parameters, ParameterType


class AuthenticationParameters(Parameters):
    parameter_definitions = {
        'redirect_uri': Parameters.REQUIRED,
        'client_id': Parameters.REQUIRED,
        'scope': ParameterType(required=True, container_type=set),
        'response_type': ParameterType(required=True, container_type=set, allowed_values={'code', 'token', 'id_token'}),

        'state': Parameters.OPTIONAL,
        # currently not used at all
        'nonce': Parameters.OPTIONAL,
        'max_age': Parameters.OPTIONAL,
        # currently not used at all
        # 'id_token_hint': Parameters.OPTIONAL,
        # 'login_hint': Parameters.OPTIONAL,
        'response_mode': ParameterType(required=False, container_type=set, allowed_values={'query', 'fragment'}),
        # currently not used at all
        # 'display': ParameterType(required=False, container_type=set,
        #                          allowed_values={'page', 'popup', 'touch', 'wap'}),
        'prompt': ParameterType(required=False, container_type=set,
                                allowed_values={'none', 'login', 'consent', 'select_account'}),
        # currently not used at all
        # 'ui_locales': ParameterType(required=False, container_type=list),
        # 'acr_values': ParameterType(required=False, container_type=list),

        # extra parameters which are provided by AuthenticationRequestView
        'username': Parameters.OPTIONAL
    }


class TokenParameters(Parameters):
    parameter_definitions = {
        'grant_type': ParameterType(required=True, container_type=set,
                                    allowed_values={'authorization_code', 'refresh_token'}),
        # authorization_code
        'code': Parameters.OPTIONAL, # required for authorization_code
        'redirect_uri': Parameters.OPTIONAL,

        # common for POST credentials instead of basic auth
        'client_id': Parameters.OPTIONAL,
        'client_secret': Parameters.OPTIONAL,

        # refresh token
        'refresh_token': Parameters.OPTIONAL,  # required for refresh_token
        'scope': Parameters.OPTIONAL
    }


