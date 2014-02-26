from ConfigParser import NoSectionError
from automatron.command import IAutomatronCommandHandler

try:
    import ujson as json
except ImportError:
    import json
import random
import urllib
from StringIO import StringIO
from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.web.client import Agent, FileBodyProducer, readBody, PartialDownloadError, getPage
from twisted.web.http_headers import Headers
from zope.interface import implements, classProvides
from automatron.plugin import IAutomatronPluginFactory, STOP
from automatron.client import IAutomatronMessageHandler
import re


URL_RE = re.compile(r'(https?://(www\.)?youtube.com/(watch)?\?(.+&)?vi?=|'
                    r'https?://(www.)?youtube.com/(vi?|embed)/|'
                    r'https?://youtu.be/)([a-zA-Z0-9_-]{11})')

DEFAULT_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
DEFAULT_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'


def flatten_dict(dd, separator='_', prefix=''):
    return {
        prefix + separator + k if prefix else k: v
        for kk, vv in dd.items()
        for k, v in flatten_dict(vv, separator, kk).items()
    } if isinstance(dd, dict) else {prefix: dd}


class YoutubePlaylistPlugin(object):
    classProvides(IAutomatronPluginFactory)
    implements(IAutomatronMessageHandler, IAutomatronCommandHandler)

    name = 'youtube_playlist'
    priority = 100

    def __init__(self, controller):
        self.controller = controller
        self.agent = Agent(reactor)

        try:
            config = dict(controller.config_file.items('google'))
        except NoSectionError:
            config = {}
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.auth_uri = config.get('auth_uri', DEFAULT_AUTH_URI)
        self.token_uri = config.get('token_uri', DEFAULT_TOKEN_URI)

    def on_command(self, client, user, command, args):
        nickname = client.parse_user(user)[0]

        if command == 'youtube-auth':
            if not self.auth_uri or not self.token_uri or not self.client_id or not self.client_secret:
                client.msg(nickname, 'Sorry, authentication is disabled.')
            elif len(args) == 1 and args[0] == 'start':
                self._on_command_auth_request(client, user)
            elif len(args) >= 2:
                self._on_command_auth_response(client, user, args[0], args[1:])
            else:
                client.msg(nickname, 'To start authentication, use: youtube-auth start')
            return STOP
        elif command == 'youtube-playlist':
            if len(args) < 2:
                client.msg(nickname, 'Syntax: youtube-playlist <playlist-id> <channel...>')
            else:
                self._on_command_playlist(client, user, args[0], args[1:])
            return STOP

    @defer.inlineCallbacks
    def _on_command_auth_request(self, client, user):
        nickname = client.parse_user(user)[0]

        url = self.auth_uri + '?' + urllib.urlencode({
            'scope': 'https://www.googleapis.com/auth/youtube',
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
            'response_type': 'code',
            'client_id': self.client_id,
        })

        try:
            response = json.loads((yield getPage(
                'https://www.googleapis.com/urlshortener/v1/url',
                method='POST',
                postdata=json.dumps({'longUrl': url}),
                headers={
                    'Content-Type': 'application/json',
                },
            )))
            url = response['id'].encode('utf-8')
            if 'error' in response:
                raise Exception(response.get('error_description', response['error']))
        except Exception as e:
            log.err(e, 'Failed to short URL')

        client.msg(nickname, 'Please visit: %s' % url)
        client.msg(nickname, 'Then use: youtube-auth <response code> <channels...>')

    @defer.inlineCallbacks
    def _on_command_auth_response(self, client, user, response_code, channels):
        nickname = client.parse_user(user)[0]

        for channel in channels:
            if not (yield self.controller.config.has_permission(client.server, channel, user, 'youtube-playlist')):
                client.msg(nickname, 'You\'re not authorized to change settings for %s' % channel)
                return

        data = {
            'code': response_code,
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }

        try:
            response = json.loads((yield getPage(
                self.token_uri,
                method='POST',
                postdata=urllib.urlencode(data),
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            )))
            if 'error' in response:
                raise Exception(response.get('error_description', response['error']))
        except Exception as e:
            log.err(e, 'Failed to retrieve or decode access token')
            client.msg(nickname, 'Failed to retrieve or decode access token.')
            return

        for channel in channels:
            access_token = response.get('access_token')
            if access_token is not None:
                access_token = access_token.encode('UTF-8')

            refresh_token = response.get('refresh_token')
            if refresh_token is not None:
                refresh_token = refresh_token.encode('UTF-8')

            self.controller.config.update_plugin_value(
                self,
                client.server,
                channel,
                'access_token',
                access_token
            )
            self.controller.config.update_plugin_value(
                self,
                client.server,
                channel,
                'refresh_token',
                refresh_token
            )

        client.msg(nickname, 'OK')

    @defer.inlineCallbacks
    def _on_command_playlist(self, client, user, playlist_id, channels):
        nickname = client.parse_user(user)[0]

        for channel in channels:
            if not (yield self.controller.config.has_permission(client.server, channel, user, 'youtube-playlist')):
                client.msg(nickname, 'You\'re not authorized to change settings for %s' % channel)
                return

        for channel in channels:
            self.controller.config.update_plugin_value(
                self,
                client.server,
                channel,
                'playlist_id',
                playlist_id
            )

        client.msg(nickname, 'OK')

    @defer.inlineCallbacks
    def on_message(self, client, user, channel, message):
        config = yield self.controller.config.get_plugin_section(self, client.server, channel)

        if not 'playlist_id' in config:
            return

        if not 'access_token' in config:
            log.msg('Missing YouTube access token for channel %s' % channel)
            return

        trigger = config.get('trigger', '!youtube')

        if message == trigger:
            items = yield self._youtube_list_playlist_videos(client, channel, config)
            if items is None:
                return
            elif items:
                self.send_youtube_message(client, channel, [random.choice(items)])
            defer.returnValue(STOP)

        elif message.startswith(trigger + '^'):
            rest = message[len(trigger) + 1:]
            try:
                n = int(rest)
            except ValueError:
                n = 1
            n = max(1, min(n, int(config.get('history_limit', 9))))

            items = yield self._youtube_list_playlist_videos(client, channel, config)
            if items is None:
                return

            self.send_youtube_message(client, channel, reversed(items[-n:]))
            defer.returnValue(STOP)

        else:
            video_ids = [match[-1] for match in URL_RE.findall(message)]
            for video_id in video_ids:
                self._add_to_playlist(client, channel, config, video_id)

    def send_youtube_message(self, client, channel, items):
        if items:
            for item in items:
                item = flatten_dict(item['snippet'], separator='.')
                message = 'https://youtu.be/%(resourceId.videoId)s - %(title)s' % item
                client.msg(channel, message.encode('UTF-8'))
        else:
            client.msg(channel, 'Playlist is empty.')

    @defer.inlineCallbacks
    def _add_to_playlist(self, client, channel, config, video_id):
        items = yield self._youtube_list_playlist_items(client, channel, config, {
            'videoId': video_id,
        })
        if items is None:
            return
        elif items:
            log.msg('Video %s is already on the playlist for channel %s.' % (video_id, channel))
            return

        result = yield self._youtube_request(
            client,
            channel,
            config,
            'POST',
            {
                'part': 'snippet',
            },
            {
                'snippet': {
                    'playlistId': config['playlist_id'],
                    'resourceId': {
                        'kind': 'youtube#video',
                        'videoId': video_id,
                    }
                }
            },
        )

        if result is None:
            log.msg('YouTube API request failed (video_id=%s).' % video_id)
        else:
            log.msg('Video %s was added to the playlist for channel %s.' % (video_id, channel))

    @defer.inlineCallbacks
    def _youtube_list_playlist_videos(self, client, channel, config, filter={}):
        items = yield self._youtube_list_playlist_items(client, channel, config, filter)
        if items is None:
            defer.returnValue(None)

        defer.returnValue([
            item
            for item in items
            if item['snippet']['resourceId']['kind'] == 'youtube#video'
        ])

    @defer.inlineCallbacks
    def _youtube_list_playlist_items(self, client, channel, config, query=None):
        query = dict({
            'part': 'snippet',
            'playlistId': config['playlist_id'],
            'maxResults': 50,
        }, **(query or {}))

        page_token = None
        items = []

        while True:
            if page_token is not None:
                query['pageToken'] = page_token

            body = yield self._youtube_request(
                client,
                channel,
                config,
                'GET',
                query
            )

            if body is not None:
                items.extend(body['items'])
                if 'nextPageToken' in body:
                    page_token = body['nextPageToken']
                    continue
            else:
                defer.returnValue(None)
            break
        defer.returnValue(sorted(items, key=lambda v: v['snippet']['position']))

    @defer.inlineCallbacks
    def _youtube_request(self, client, channel, config, method, query=None, body=None):
        attempts = 0
        while attempts < 2:
            attempts += 1
            response, response_body = yield self._request(
                method,
                'https://www.googleapis.com/youtube/v3/playlistItems',
                dict(query, access_token=config['access_token']),
                body,
            )

            if response.code == 200:
                defer.returnValue(response_body)
            elif response.code == 401:
                result = yield self._refresh_access_token(client, channel, config)
                if result is True:
                    continue
            else:
                log.msg('YouTube API query failed: %d %s' % (response.code, response.phrase))
            break

    @defer.inlineCallbacks
    def _refresh_access_token(self, client, channel, config):
        if self.client_id is None or self.client_secret is None:
            log.msg('YouTube API access token expired but client id and/or secret are unavailable.')
            defer.returnValue(False)

        if not self.token_uri:
            log.msg('YouTube API access token expired but token uri is unavailable.')
            defer.returnValue(False)

        if not 'refresh_token' in config:
            log.msg('YouTube API access token expired but refresh_token is unavailable.')
            defer.returnValue(False)

        response, body = yield self._request('POST', self.token_uri, None, {
            'refresh_token': config['refresh_token'],
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }, 'application/x-www-form-urlencoded')

        if response.code != 200:
            log.msg('Failed to refresh access_token: %d %s %s' % (response.code, response.phrase, body['error']))
            defer.returnValue(False)
        else:
            log.msg('Succesfully refreshed access_token.')
            config['access_token'] = body['access_token']
            yield self.controller.config.update_plugin_value(
                self,
                client.server,
                channel,
                'access_token',
                body['access_token']
            )
            defer.returnValue(True)

    @defer.inlineCallbacks
    def _request(self, method, url, query=None, body=None, content_type='application/json'):
        if query is not None:
            url += '?' + urllib.urlencode(query)

        if body is not None:
            if content_type == 'application/json':
                body = json.dumps(body)
            elif content_type == 'application/x-www-form-urlencoded':
                body = urllib.urlencode(body)
            else:
                body = str(body)
            body = FileBodyProducer(StringIO(body))

        response = yield self.agent.request(
            method,
            url,
            Headers({
                'User-Agent': ['Automatron YouTube Playlist Plugin'],
                'Content-Type': [content_type],
            }),
            body,
        )

        try:
            body = yield readBody(response)
        except PartialDownloadError as e:
            body = e.response

        content_type_headers = response.headers.getRawHeaders('content-type')
        for ct in content_type_headers:
            if ct.split(';')[0].lower() == 'application/json':
                try:
                    body = json.loads(body)
                except ValueError:
                    log.msg('Unable to decode json body: ' + body)
                    log.err()
                    defer.returnValue((None, None))

        defer.returnValue((response, body))
