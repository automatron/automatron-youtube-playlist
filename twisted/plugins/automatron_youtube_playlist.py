import json
import random
import urllib
from StringIO import StringIO
from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.web.client import Agent, FileBodyProducer, readBody, PartialDownloadError
from twisted.web.http_headers import Headers
from zope.interface import implements, classProvides
from automatron.plugin import IAutomatronPluginFactory, STOP
from automatron.client import IAutomatronMessageHandler
import re


URL_RE = re.compile(r'(https?://(www\.)?youtube.com/(watch)?\?(.+&)?vi?=|'
                    r'https?://(www.)?youtube.com/(vi?|embed)/|'
                    r'https?://youtu.be/)([a-zA-Z0-9_-]{11})')


def flatten_dict(dd, separator='_', prefix=''):
    return {
        prefix + separator + k if prefix else k: v
        for kk, vv in dd.items()
        for k, v in flatten_dict(vv, separator, kk).items()
    } if isinstance(dd, dict) else {prefix: dd}


class YoutubePlaylistPlugin(object):
    classProvides(IAutomatronPluginFactory)
    implements(IAutomatronMessageHandler)

    name = 'youtube_playlist'
    priority = 100

    def __init__(self, controller):
        self.controller = controller
        self.agent = Agent(reactor)

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
                if not 'refresh_token' in config:
                    log.msg('YouTube API access token expired but no refresh_token available.')
                else:
                    log.msg('Refreshing YouTube API access token.')
                    result = yield self._refresh_access_token(client, channel, config)
                    if result is True:
                        continue
            else:
                log.msg('YouTube API query failed: %d %s' % (response.code, response.phrase))
            break

    @defer.inlineCallbacks
    def _refresh_access_token(self, client, channel, config):
        response, body = yield self._request('POST', config['token_uri'], None, {
            'refresh_token': config['refresh_token'],
            'grant_type': 'refresh_token',
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
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
