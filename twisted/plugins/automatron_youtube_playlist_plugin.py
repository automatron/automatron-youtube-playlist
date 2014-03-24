from ConfigParser import NoOptionError
import datetime
from automatron.backend.command import IAutomatronCommandHandler
from automatron.controller.controller import IAutomatronClientActions
from automatron.core.event import STOP
from automatron_youtube_playlist.config_oauth_requester import ConfigOAuthRequesterFactory
from txgoogleapi import Google, UnauthRequester, ApiKeyRequester
import random
import urllib
from twisted.internet import defer
from twisted.python import log
from zope.interface import implements, classProvides
from automatron.backend.plugin import IAutomatronPluginFactory
from automatron.controller.client import IAutomatronMessageHandler
import re
try:
    import ujson as json
except ImportError:
    import json


URL_RE = re.compile(r'(https?://(www\.)?youtube.com/(watch)?\?(.+&)?vi?=|'
                    r'https?://(www.)?youtube.com/(vi?|embed)/|'
                    r'https?://youtu.be/)([a-zA-Z0-9_-]{11})')

MAX_VIDEOS_PER_PLAYLIST = 200


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
        self.requester_factory = ConfigOAuthRequesterFactory(self, controller)

    def _msg(self, server, user, message):
        self.controller.plugins.emit(
            IAutomatronClientActions['message'],
            server,
            user,
            message
        )

    def on_command(self, server, user, command, args):
        if command != 'youtube':
            return

        if len(args) == 0:
            self._help(server, user)
        else:
            subcommand, args = args[0], args[1:]
            self._on_command(server, user, subcommand, args)
        return STOP

    def _help(self, server, user):
        for line in """Usage: youtube <task> [args...]
Available tasks:
youtube auth start                           - Start authentication
youtube auth <response code> <channel...>    - Finish authentication
youtube title <title> <channel...>           - Set playlist title prefix
youtube playlist <playlist ID> <channel...>  - Set youtube playlist ID
youtube trigger <trigger> <channel...>       - Change channel trigger""".split('\n'):
            self._msg(server['server'], user, line)

    @defer.inlineCallbacks
    def _on_command(self, server, user, subcommand, args):
        if subcommand == 'auth':
            if not self.requester_factory.is_configured():
                self._msg(server['server'], user, 'Sorry, authentication is disabled.')
            elif len(args) == 1 and args[0] == 'start':
                self._on_auth_start(server, user)
            elif len(args) >= 2:
                if (yield self._verify_permissions(server, user, args[1:])):
                    self._on_auth_response(server, user, args[0], args[1:])
            else:
                self._help(server, user)
        elif subcommand in ('title', 'playlist', 'trigger') and len(args) >= 2:
            if (yield self._verify_permissions(server, user, args[1:])):
                self._on_update_setting(server, user, args[1:], subcommand, args[0])
        else:
            self._help(server, user)

    @defer.inlineCallbacks
    def _verify_permissions(self, server, user, channels):
        for channel in channels:
            if not (yield self.controller.config.has_permission(server['server'], channel, user, 'youtube-playlist')):
                self._msg(server['server'], user, 'You\'re not authorized to change settings for %s' % channel)
                defer.returnValue(False)

        defer.returnValue(True)

    @defer.inlineCallbacks
    def _on_auth_start(self, server, user):
        url = self.requester_factory.auth_uri + '?' + urllib.urlencode({
            'response_type': 'code',
            'client_id': self.requester_factory.client_id,
            'scope': 'https://www.googleapis.com/auth/youtube',
            'redirect_uri': 'urn:ietf:wg:oauth:2.0:oob',
            'access_type': 'offline',
        })

        try:
            api_key = self.controller.config_file.get('google', 'api_key')
        except NoOptionError:
            api_key = None
        if api_key:
            requester = ApiKeyRequester(api_key)
        else:
            requester = UnauthRequester()
        google = Google(requester)
        try:
            response = yield google.urlshortener.url.insert(body={
                'longUrl': url,
            })
            url = response['id'].encode('utf-8')
        except Exception as e:
            log.err(e, 'Failed to shorten URL')

        self._msg(server['server'], user, 'Please visit: %s' % url)
        self._msg(server['server'], user, 'Then use: youtube auth <response code> <channels...>')

    @defer.inlineCallbacks
    def _on_auth_response(self, server, user, response_code, channels):
        request = self.requester_factory(server['server'], channels[0], {})
        try:
            yield request.request_access_token(response_code)
        except Exception as e:
            log.err(e, 'Failed to retrieve or decode access token')
            self._msg(server['server'], user, 'Failed to retrieve or decode the access token.')
            return

        for channel in channels[1:]:
            r = self.requester_factory(server['server'], channel, {})
            r.access_token = request.access_token
            r.refresh_token = request.refresh_token

        self._msg(server['server'], user, 'OK')

    def _on_update_setting(self, server, user, channels, key, value):
        for channel in channels:
            self.controller.config.update_plugin_value(
                self,
                server['server'],
                channel,
                key,
                value
            )

        self._msg(server['server'], user, 'OK')

    def on_message(self, server, user, channel, message):
        return self._on_message(server, channel, message)

    @defer.inlineCallbacks
    def _on_message(self, server, channel, message):
        config = yield self.controller.config.get_plugin_section(self, server['server'], channel)

        title_prefix = config.get('title')
        playlist_id = config.get('playlist')
        if not title_prefix and not playlist_id:
            return

        trigger = config.get('trigger', '!youtube')

        requester = self.requester_factory(server['server'], channel, config)
        google = Google(requester)

        if message == trigger:
            d = self._youtube_list_playlist_videos(google, playlist_id)
            d.addCallback(lambda items: self._emit_videos(
                server,
                channel,
                [random.choice(items)] if items else []
            ))
            d.addErrback(lambda e: log.err(e, 'Failed to retrieve playlist items'))
            defer.returnValue(STOP)

        elif message.startswith(trigger + '^'):
            rest = message[len(trigger) + 1:]
            try:
                n = int(rest)
            except ValueError:
                n = 1
            n = max(1, min(n, int(config.get('history_limit', 9))))

            d = self._youtube_list_playlist_videos(google, playlist_id)
            d.addCallback(lambda items: self._emit_videos(
                server,
                channel,
                reversed(items[-n:]) if items else []
            ))
            defer.returnValue(STOP)

        else:
            video_ids = [match[-1] for match in URL_RE.findall(message)]
            if video_ids and playlist_id:
                try:
                    playlist_length = yield self._get_playlist_length(google, playlist_id)
                except Exception as e:
                    log.err(e, 'Failed to get playlist length, creating a new one')
                    playlist_id = None
                    playlist_length = 0
            else:
                playlist_length = 0

            for video_id in video_ids:
                if not playlist_id or playlist_length >= MAX_VIDEOS_PER_PLAYLIST:
                    if not title_prefix:
                        log.msg('Could not add video because playlist was full and no title prefix is set.')
                        return

                    playlist_id = yield self._create_playlist(google, title_prefix)
                    self.controller.config.update_plugin_value(
                        self,
                        server['server'],
                        channel,
                        'playlist',
                        playlist_id
                    )
                    playlist_length = 0

                if (yield self._add_to_playlist(google, playlist_id, video_id)):
                    playlist_length += 1

    def _emit_videos(self, server, channel, items):
        if items:
            for item in items:
                item = flatten_dict(item['snippet'], separator='.')
                message = 'https://youtu.be/%(resourceId.videoId)s - %(title)s' % item
                self._msg(server['server'], channel, message.encode('UTF-8'))
        else:
            self._msg(server['server'], channel, 'Playlist is empty.')

    def _get_playlist_length(self, google, playlist_id):
        d = google.youtube.playlistItems.list(part='snippet', playlistId=playlist_id, maxResults=0)
        d.addCallback(lambda data: data['pageInfo']['totalResults'])
        return d

    @defer.inlineCallbacks
    def _add_to_playlist(self, google, playlist_id, video_id):
        items = yield self._youtube_list_playlist_items(google, playlist_id, video_id)
        if items:
            log.msg('Video %s is already on the playlist.' % video_id)
            defer.returnValue(False)

        try:
            yield google.youtube.playlistItems.insert(
                part='snippet',
                body={
                    'snippet': {
                        'playlistId': playlist_id,
                        'resourceId': {
                            'kind': 'youtube#video',
                            'videoId': video_id,
                        }
                    }
                },
            )
            log.msg('Added video %s to the playlist' % video_id)
            defer.returnValue(True)
        except Exception as e:
            log.err(e, 'Failed to add video %s to the playlist' % video_id)
            defer.returnValue(False)

    @defer.inlineCallbacks
    def _create_playlist(self, google, title_prefix):
        playlist_id = (yield google.youtube.playlists.insert(part='snippet', body={
            'snippet': {
                'title': '%s - %s' % (
                    title_prefix,
                    datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ),
            },
        }))['id'].encode('utf-8')
        log.msg('Created new playlist %s' % playlist_id)
        defer.returnValue(playlist_id)

    @defer.inlineCallbacks
    def _youtube_list_playlist_videos(self, google, playlist_id, video_id=None):
        items = yield self._youtube_list_playlist_items(google, playlist_id, video_id)
        defer.returnValue([
            item
            for item in items
            if item['snippet']['resourceId']['kind'] == 'youtube#video'
        ])

    @defer.inlineCallbacks
    def _youtube_list_playlist_items(self, google, playlist_id, video_id=None):
        if playlist_id is None:
            defer.returnValue([])

        query = dict({
            'part': 'snippet',
            'playlistId': playlist_id,
            'videoId': video_id,
            'maxResults': 50,
        })

        items = []

        page_token = None
        while True:
            if page_token is not None:
                query['pageToken'] = page_token

            body = yield google.youtube.playlistItems.list(**query)
            items.extend(body['items'])
            if not 'nextPageToken' in body:
                break
            page_token = body['nextPageToken']

        defer.returnValue(sorted(items, key=lambda v: v['snippet']['position']))
