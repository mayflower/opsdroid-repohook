from aiohttp.web import Request
from opsdroid.events import Message
from opsdroid.matchers import match_webhook, match_parse
from opsdroid.skill import Skill

import json
# import config

from aiohttp.web import Request, Response
import shlex

# from . import providers
from .providers import GitLabHandlers, GithubHandlers, SUPPORTED_EVENTS, DEFAULT_EVENTS

DEFAULT_CONFIG = {'default_events': DEFAULT_EVENTS, 'repositories': {}, }

REQUIRED_HEADERS = [('X-Github-Event', 'X-Gitlab-Event')]
#VALIDATION_ENABLED = getattr(config, 'VALIDATE_SIGNATURE', True)
#if VALIDATION_ENABLED:
#    REQUIRED_HEADERS.append(('X-Hub-Signature', 'X-Gitlab-Token'), )

HELP_MSG = ('Please see the output of `repohook help` for usage '
            'and configuration instructions.')

REPO_UNKNOWN = 'The repository `{0}` is unknown to me.'
EVENT_UNKNOWN = 'Unknown event `{0}`, skipping.'

README = 'https://github.com/daenney/err-repohook/blob/master/README.rst'


class RepoHook(Skill):
    def __init__(self, opsdroid, config):
        super(RepoHook, self).__init__(opsdroid, config)
        self.github = GithubHandlers()
        self.gitlab = GitLabHandlers()

    #################################################################
    # Convenience methods to get, check or set configuration options.
    #################################################################
    async def load(self, key):
        return await self.opsdroid.memory.get(key)

    async def store(self, key, value):
        await self.opsdroid.memory.put(key, value)

    async def delete(self, key):
        await self.opsdroid.memory.delete(key)

    async def clear_repo(self, repo):
        """Completely remove a repository's configuration."""
        if self.has_repo(repo):
            await self.delete(f"repositories-{repo}")

    async def clear_route(self, repo, room):
        """Remove a route from a repository."""
        if self.has_route(repo, room):
            repo_data = await (await self.get_repo(repo))
            repo_data['routes'].pop(room)
            await self.store(f"repositories-{repo}", repo_data)

    async def has_repo(self, repo):
        """Check if the repository is known."""
        if await self.get_repo(repo) is None:
            return False
        else:
            return True

    async def has_route(self, repo, room):
        """Check if we have a route for this repository to that room."""
        if await self.get_route(repo, room) is None:
            return False
        else:
            return True

    async def get_defaults(self):
        """Return the default events that get relayed."""
        return await self.load('default_events')

    async def get_events(self, repo, room):
        """Return all the events being relayed for this combination of
        repository and room, aka a route.
        """
        return (await self.get_repo(repo)) or {} \
            .get('routes', {}) \
            .get(room, {}) \
            .get('events')

    async def get_repo(self, repo):
        """Return the repo's configuration or None."""
        return await self.load(f"repositories-{repo}")

    async def get_route(self, repo, room):
        """Return the configuration of this route."""
        return (await self.get_repo(repo)) or {} \
            .get('routes', {}) \
            .get(room)

    async def get_routes(self, repo):
        """Fetch the routes for a repository.
        Always check if the repository exists before calling this.
        """
        return (await self.get_repo(repo)) or {} \
            .get('routes', {}) \
            .keys()

    async def get_token(self, repo):
        """Returns the token for a repository.

        Be **very** careful as to where you call this as this returns the
        plain text, uncensored token.
        """
        return (await self.get_repo(repo)) or {} \
            .get('token')

    async def set_defaults(self, defaults):
        """Set which events are relayed by default."""
        await self.store('default_events', defaults)

    async def set_events(self, repo, room, events):
        """Set the events to be relayed for this combination of repository
        and room."""
        if self.has_route(repo, room):
            repo_data = await (await self.get_repo(repo))
            repo_data[room] = repo_data[room] or {}  # todo needed?
            repo_data[room]['events'] = events
            await self.store(f"repositories-{repo}", repo_data)

    async def set_route(self, repo, room):
        """Create a configuration entry for this route.

        If the repository is unknown to us, add the repository first.
        """
        if self.has_repo(repo):
            repo_data = await self.load(repo)
        else:
            repo_data = { 'routes': {}, 'token': None }
        repo_data['routes'][room] = {}
        await self.store(repo, repo_data)

    async def set_token(self, repo, token):
        """Set the token for a repository."""
        if self.has_repo(repo):
            repo_data = await self.load(repo)
        else:
            repo_data = { 'routes': {}, 'token': None }
        repo_data['token'] = token
        await self.store(repo, repo_data)

    async def show_repo_config(self, repo):
        """Builds up a complete list of rooms and events for a repository."""
        if self.has_repo(repo):
            message = ['Routing `{0}` to:'.format(repo)]
            repo_data = await self.get_repo(repo)
            # event_msgs = [f' • `{room}` for events: {md_escape(events)}' # todo <-
            event_msgs = [f' • `{room}` for events: {events}'
                          for room in repo_data['routes'].keys()
                          for events in repo_data['routes'][room].get('events', {}).keys()
                          ]
            message.append(event_msgs)
            return '\n'.join(message)
        else:
            return REPO_UNKNOWN.format(repo)

    ###########################################################
    # Commands for the user to get, set or clear configuration.
    ###########################################################

    def _get_args(self, message):
        return shlex.split(message.entities.get('args', {}).get('values'))

    @match_parse("repohook")
    async def repohook(self, message):
        """RepoHook root command, return usage information."""
        await self.repohook_help(message)

    @match_parse("repohook help")
    async def repohook_help(self, message):
        """Output help."""
        halp = []
        halp.append('This plugin has multiple commands: ')
        halp.append(' • config: to display the full configuration of '
                       'this plugin (not human friendly)')
        halp.append(' • route `<repo> <room>`: to relay messages from '
                       '`<repo>` to `<room>` for events '
                       # '{0}'.format(md_escape(' '.join(self.get_defaults())))) # todo <-
                       '{0}'.format(' '.join(await self.get_defaults())))
        halp.append(' • route `<repo> <room> <events>`: to relay '
                       'messages from `<repo>` to `<room>` for `<events>`')
        halp.append(' • routes `<repo>`: show routes for this repository')
        halp.append(' • routes: to display all routes')
        halp.append(' • global route <room>: to set a route for global events')
        halp.append(' • defaults <events>: to configure the events we '
                       'should forward by default')
        halp.append(' • defaults: to show the events to be forwarded '
                       'by default')
        halp.append(' • token `<repo>`: to configure the repository '
                       'secret')
        halp.append('Please see {0} for more information.'.format(README))
        await message.respond('\n'.join(halp))

    # @botcmd(admin_only=True) todo <-
    @match_parse("repohook config")
    async def repohook_config(self, message):
        """Returns the current configuration of the plugin."""
        # pprint can't deal with nested dicts, json.dumps is aces.
        await message.respond(json.dumps(self.config, indent=4, sort_keys=True))

    # @botcmd(admin_only=True) todo <-
    @match_parse("repohook reset")
    async def repohook_reset(self, message):
        """Nuke the complete configuration."""
        # self.config = DEFAULT_CONFIG
        # self.save_config()
        # FIXME
        await message.respond('this command has not been ported yet!')



    @match_parse("repohook defaults")
    async def repohook_defaults(self, message):
        await message.respond('Events routed by default: '
                              '{0}.'.format(' '.join(await self.get_defaults())))
                        # '{0}.'.format(md_escape(' '.join(self.get_defaults())))) # todo <-


    @match_parse("repohook defaults {args}")
    async def repohook_defaults_args(self, message):
        """Get or set what events are relayed by default for new routes."""
        args = self._get_args(message)
        events = []
        for event in args:
            if event in SUPPORTED_EVENTS:
                events.append(event)
            else:
                yield EVENT_UNKNOWN.format(event)
        await self.set_defaults(events)
        await message.respond('Done. Newly created routes will default to '
               'receiving: {0}.'.format(' '.join(events)))

    @match_parse("repohook route {args}")
    async def repohook_route(self, message, args):
        """Map a repository to a chatroom, essentially creating a route.

        This takes two or three arguments: author/repo, a chatroom and
        optionally a list of events.

        If you do not specify a list of events the route will default to
        receiving the events configured as 'default_events'.
        """
        args = self._get_args(message)
        msgs = []
        if len(args) >= 2:
            repo = args[0]
            room = args[1]
            # Slicing on an index that, potentially, doesn't exist returns
            # an empty list instead of raising an IndexError
            events = args[2:]

            if not self.has_route(repo, room):
                await self.set_route(repo, room)

            if events:
                for event in events[:]:
                    if event not in SUPPORTED_EVENTS:
                        events.remove(event)
                        msgs.append(EVENT_UNKNOWN.format(event))
            else:
                events = self.get_defaults()
            await self.set_events(repo, room, events)
            msgs.append('Done. Relaying messages from `{0}` to `{1}` for '
                                  'events: {2}'.format(repo, room, ' '.join(events)))
                   # 'events: {2}'.format(repo, room, md_escape(' '.join(events)))) # todo <-
            if self.get_token(repo) is None:
                msgs.append("Don't forget to set the token for `{0}`. Instructions "
                       "on how to do so and why can be found "
                       "at: {1}.".format(repo, README))
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))

    @match_parse("repohook routes")
    async def repohook_routes(self, message):
        """Displays the routes for all repositories."""
        repos = [] # await self.get_repos() # fixme implement
        msgs = []
        if repos:
            msgs.append("You asked for it, here are all the repositories, the "
                   "rooms and associated events that are relayed:")
            msgs.extend([await self.show_repo_config(repo) for repo in repos])
        else:
            msgs.append('No repositories configured, nothing to show.')
        await message.respond('\n'.join(msgs))

    @match_parse("repohook routes {args}")
    async def repohook_routes(self, message):
        """Displays the routes for one, multiple or all repositories."""
        args = self._get_args(message)
        msgs = []
        for repo in args:
            if self.has_repo(repo):
                msgs.append(await self.show_repo_config(repo))
            else:
                msgs.append(REPO_UNKNOWN.format(repo))
        await message.respond('\n'.join(msgs))

    @match_parse("repohook token {args}")
    async def repohook_token(self, message):
        """Register the secret token for a repository.

        This token is needed to validate the incoming request as coming from
        the repository. It must be configured on your repository's webhook
        settings too.
        """
        args = self._get_args(message)
        if len(args) != 2:
            await message.respond(HELP_MSG)
        else:
            repo = args[0]
            token = args[1]
            if await self.has_repo(repo):
                await self.set_token(repo, token)
                await message.respond('Token set for {0}.'.format(repo))
            else:
                await message.respond(REPO_UNKNOWN.format(repo))

    @match_parse("repohook remove {args}")
    async def repohook_remove(self, message):
        """Remove a route or a repository.

        If only one argument is passed all configuration for that repository
        is removed.

        When two arguments are passed that specific route is removed. If this
        was the last route any remaining configuration for the repository is
        removed too. With only one route remaining this essentially achieves
        the same result as calling this with only the repository as argument.
        """
        args = self._get_args(message)
        msgs = []
        if len(args) == 1:
            repo = args[0]
            await self.clear_repo(repo)
            msgs.append('Removed all configuration for {0}.'.format(repo))
        elif len(args) == 2:
            repo = args[0]
            room = args[1]
            await self.clear_route(repo, room)
            msgs.append('Removed route for {0} to {1}.'.format(repo, room))
            if not await self.get_routes(repo):
                await self.clear_repo(repo)
                msgs.append('No more routes for {0}, removing remaining '
                            'configuration.'.format(repo))
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))

    @match_parse("repohook global {args}")
    async def repohook_global(self, message):
        """Set a global route"""
        args = self._get_args(message)
        msgs = []
        key = "global_route"
        if len(args) == 1:
            await self.delete(key)
            msgs.append('Removed global route.')
        elif len(args) == 2:
            room = args[1]
            await self.store(key, room)
            msgs.append('Set global route to {}.'.format(room))
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))

    @match_webhook('test')
    async def hello(self, event: Request):
        await self.opsdroid.send(Message(str('Oy there')))
