from ConfigParser import NoSectionError
from txgoogleapi import OAuthRequester
from txgoogleapi.oauth_requester import DEFAULT_TOKEN_URI


DEFAULT_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
NOT_SET = object()


class ConfigOAuthRequester(OAuthRequester):
    def __init__(self, factory, server, channel, config):
        self.factory = factory
        self.server = server
        self.channel = channel
        self._refresh_token = NOT_SET
        self._access_token = NOT_SET

        super(ConfigOAuthRequester, self).__init__(
            token_uri=self.factory.token_uri,
            client_id=self.factory.client_id,
            client_secret=self.factory.client_secret,
            access_token=config.get('access_token'),
            refresh_token=config.get('refresh_token'),
        )

    def _get_access_token(self):
        return self._access_token

    def _set_access_token(self, value):
        old_token, self._access_token = self._access_token, value
        if old_token is not NOT_SET:
            self.factory.controller.config.update_plugin_value(
                self.factory.owner,
                self.server,
                self.channel,
                'access_token',
                value
            )

    access_token = property(_get_access_token, _set_access_token)

    def _get_refresh_token(self):
        return self._refresh_token

    def _set_refresh_token(self, value):
        old_token, self._refresh_token = self._refresh_token, value
        if old_token is not NOT_SET:
            self.factory.controller.config.update_plugin_value(
                self.factory.owner,
                self.server,
                self.channel,
                'refresh_token',
                value
            )

    refresh_token = property(_get_refresh_token, _set_refresh_token)


class ConfigOAuthRequesterFactory(object):
    def __init__(self, owner, controller):
        self.owner = owner
        self.controller = controller

        try:
            config = dict(controller.config_file.items('google'))
        except NoSectionError:
            config = {}

        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.token_uri = config.get('token_uri', DEFAULT_TOKEN_URI)
        self.auth_uri = config.get('auth_uri', DEFAULT_AUTH_URI)

    def is_configured(self):
        return self.client_id is not None and self.client_secret is not None and self.auth_uri is not None and \
            self.token_uri is not None

    def __call__(self, server, channel, config):
        return ConfigOAuthRequester(self, server, channel, config)
