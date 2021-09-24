from opsdroid.events import Message
from opsdroid.matchers import match_webhook, match_parse
from opsdroid.skill import Skill
from opsdroid.core import OpsDroid

import json
import textwrap

from aiohttp.web import Request, Response
import shlex

import logging

from .providers import GitLabHandlers, GithubHandlers, SUPPORTED_EVENTS, DEFAULT_EVENTS

DEFAULT_CONFIG = {'default_events': DEFAULT_EVENTS, 'repositories': {}, }

REQUIRED_HEADERS = [('X-Github-Event', 'X-Gitlab-Event')]

HELP_MSG = ('Please see the output of `repohook help` for usage '
            'and configuration instructions.')

REPO_UNKNOWN = 'The repository `{0}` is unknown to me.'
EVENT_UNKNOWN = 'Unknown event `{0}`, skipping.'

README = 'https://github.com/daenney/err-repohook/blob/master/README.rst'

logger = logging.getLogger(__name__)


class RepoHook(Skill):
    def __init__(self, opsdroid: OpsDroid, config):
        super(RepoHook, self).__init__(opsdroid, config)
        self.github = GithubHandlers()
        self.gitlab = GitLabHandlers()
        self.validation_enabled = config.get('validate-signature', True)
        if self.validation_enabled:
            REQUIRED_HEADERS.append(('X-Hub-Signature', 'X-Gitlab-Token'), )

    async def _load_defaults(self):
        await self.store('default_events', await self.load('default_events') or DEFAULT_EVENTS)

    #################################################################
    # Convenience methods to get, check or set configuration options.
    #################################################################
    async def load(self, key):
        return await self.opsdroid.memory.get(key)

    async def store(self, key, value):
        await self.opsdroid.memory.put(key, value)

    async def delete(self, key):
        await self.opsdroid.memory.delete(key)

    async def get_repos(self):
        return (await self.load("repos")) or []

    async def set_repos(self, repos):
        return await self.store("repos", repos)

    async def clear_repo(self, repo):
        """Completely remove a repository's configuration."""
        if await self.has_repo(repo):
            await self.delete(f"repositories-{repo}")
            repos = await self.load("repos")
            new_repos = [r for r in repos if r != repo]
            await self.set_repos(new_repos)

    async def clear_route(self, repo, room):
        """Remove a route from a repository."""
        repo_data = await self.get_repo(repo)
        repo_data['routes'].pop(room)
        await self.store(f"repositories-{repo}", repo_data)

    async def has_repo(self, repo):
        """Check if the repository is known."""
        return bool(await self.get_repo(repo))

    async def has_route(self, repo, room):
        """Check if we have a route for this repository to that room."""
        rd = await self.get_route(repo, room)
        return rd is not None

    async def get_defaults(self):
        """Return the default events that get relayed."""
        await self._load_defaults()
        return await self.load('default_events')

    async def get_events(self, repo, room):
        """Return all the events being relayed for this combination of
        repository and room, aka a route.
        """
        rd = await self.get_repo(repo)
        if rd:
            return rd.get('routes', {}).get(room, {}).get("events", [])
        else:
            return []

    async def get_repo(self, repo):
        """Return the repo's configuration or None."""
        return await self.load(f"repositories-{repo}")

    async def get_route(self, repo, room):
        """Return the configuration of this route."""
        rd = await self.get_repo(repo)
        if rd:
            return rd.get('routes', {}).get(room)
        else:
            return None

    async def get_routes(self, repo):
        """Fetch the routes for a repository.
        Always check if the repository exists before calling this.
        """
        return list((await self.get_repo(repo)).get('routes', {}).keys())

    async def get_token(self, repo):
        """Returns the token for a repository.

        Be **very** careful as to where you call this as this returns the
        plain text, uncensored token.
        """
        return (await self.get_repo(repo)).get('token')

    async def set_defaults(self, defaults):
        """Set which events are relayed by default."""
        await self.store('default_events', defaults)

    async def set_events(self, repo, room, events):
        """Set the events to be relayed for this combination of repository
        and room."""
        if await self.has_route(repo, room):
            repo_data = await self.get_repo(repo)
            repo_data['routes'][room] = repo_data['routes'].get(room, {})  # todo needed?
            repo_data['routes'][room]['events'] = events
            await self.store(f"repositories-{repo}", repo_data)

    async def set_route(self, repo, room):
        """Create a configuration entry for this route.

        If the repository is unknown to us, add the repository first.
        """
        repo_data = {'routes': {}, 'token': None}
        if await self.has_repo(repo):
            repo_data = await self.get_repo(repo)
        repo_data['routes'][room] = {}
        await self.store(f"repositories-{repo}", repo_data)
        all_repos = await self.get_repos()
        if repo not in all_repos:
            all_repos.append(repo)
            await self.set_repos(all_repos)

    async def set_token(self, repo, token):
        """Set the token for a repository."""
        repo_data = await self.get_repo(repo)
        repo_data['token'] = token
        await self.store(f"repositories-{repo}", repo_data)

    async def show_repo_config(self, repo):
        """Builds up a complete list of rooms and events for a repository."""
        if await self.has_repo(repo):
            msgs = [f'Routing `{repo}` to:']
            repo_data = await self.get_repo(repo)
            # event_msgs = [f' • `{room}` for events: {md_escape(events)}' # todo <-
            for room in repo_data['routes'].keys():
                msgs.append(f' • `{room}` for events: {" ".join(await self.get_events(repo, room))}')
            return '\n'.join(msgs)
        else:
            return REPO_UNKNOWN.format(repo)

    ###########################################################
    # Commands for the user to get, set or clear configuration.
    ###########################################################

    def _get_args(self, message):
        return shlex.split(message.entities.get('args', {}).get('value'))

    @match_parse("repohook")
    async def repohook(self, message):
        """RepoHook root command, return usage information."""
        await self.repohook_help(message)

    @match_parse("repohook help")
    async def repohook_help(self, message):
        """Output help."""
        # '{0}'.format(md_escape(' '.join(self.get_defaults())))) # todo <-
        defaults = await self.get_defaults()
        halp = f"""
        This plugin has multiple commands:
         • config: to display the full configuration of
                       this plugin (not human friendly)
         • route `<repo> <room>`: to relay messages from
                       `<repo>` to `<room>` for events
                       {' '.join(defaults)}
         • route `<repo> <room> <events>`: to relay
                       messages from `<repo>` to `<room>` for `<events>`
         • routes `<repo>`: show routes for this repository
         • routes: to display all routes
         • global route set <room>: to set a route for global events
         • global route disable: to disable global events
         • defaults <events>: to configure the events we
                       should forward by default
         • defaults: to show the events to be forwarded
                       by default
         • token `<repo>`: to configure the repository
                       secret
        Please see {README} for more information.
        """
        await message.respond(textwrap.dedent(halp))

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
                await message.respond(EVENT_UNKNOWN.format(event))
        await self.set_defaults(events)
        await message.respond('Done. Newly created routes will default to '
               'receiving: {0}.'.format(' '.join(events)))

    @match_parse("repohook route {args}")
    async def repohook_route(self, message):
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

            if not await self.has_route(repo, room):
                await self.set_route(repo, room)

            if events:
                for event in events[:]:
                    if event not in SUPPORTED_EVENTS:
                        events.remove(event)
                        msgs.append(EVENT_UNKNOWN.format(event))
            else:
                events = await self.get_defaults()
            await self.set_events(repo, room, events)
            msgs.append('Done. Relaying messages from `{0}` to `{1}` for '
                                  'events: {2}'.format(repo, room, ' '.join(events)))
                   # 'events: {2}'.format(repo, room, md_escape(' '.join(events)))) # todo <-
            if await self.get_token(repo) is None:
                msgs.append("Don't forget to set the token for `{0}`. Instructions "
                       "on how to do so and why can be found "
                       "at: {1}.".format(repo, README))
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))

    @match_parse("repohook routes")
    async def repohook_routes(self, message):
        """Displays the routes for all repositories."""
        repos = await self.get_repos()
        msgs = []
        if repos:
            msgs.append("You asked for it, here are all the repositories, the "
                   "rooms and associated events that are relayed:")
            msgs.extend([await self.show_repo_config(repo) for repo in repos])
        else:
            msgs.append('No repositories configured, nothing to show.')
        await message.respond('\n'.join(msgs))

    @match_parse("repohook routes {args}")
    async def repohook_routes_args(self, message):
        """Displays the routes for one, multiple or all repositories."""
        args = self._get_args(message)
        msgs = []
        for repo in args:
            if await self.has_repo(repo):
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
            if await self.has_route(repo, room):
                await self.clear_route(repo, room)
                msgs.append('Removed route for {0} to {1}.'.format(repo, room))
                routes = await self.get_routes(repo)
                if len(routes) == 0:
                    await self.clear_repo(repo)
                    msgs.append('No more routes for {0}, removing remaining '
                                'configuration.'.format(repo))
            else:
                msgs.append(f"No such route {room} for repo {repo}. Aborting. ")
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))

    @match_parse("repohook global")
    async def repohook_global(self, message):
        """Set a global route"""
        await message.respond(HELP_MSG)

    @match_parse("repohook global {args}")
    async def repohook_global_args(self, message):
        """Set a global route"""
        args = self._get_args(message)
        msgs = []
        key = "global_route"
        if len(args) == 1 and args[0] == "disable":
            await self.delete(key)
            msgs.append('Removed global route.')
        elif len(args) == 2 and args[0] == "set":
            room = args[1]
            await self.store(key, room)
            msgs.append('Set global route to {}.'.format(room))
        else:
            msgs.append(HELP_MSG)
        await message.respond('\n'.join(msgs))


    @match_webhook('')
    async def receive(self, request: Request):
        """Handle the incoming payload.

        Here be dragons.

        Validate the payload as best as we can and then delegate the creation
        of a sensible message to a function specific to this event. If no such
        function exists, use a generic message function.

        Once we have a message, route it to the appropriate channels.
        """

        event_type = None
        provider = None
        if not await self.validate_incoming(request):
            logger.warning('Request is invalid {0}'.format(str(vars(request))))
            return Response(status=400)

        if 'X-Github-Event' in request.headers:
            event_type = request.headers['X-Github-Event'].lower()
            provider = self.github
        elif 'X-Gitlab-Event' in request.headers:
            event_type = request.headers['X-Gitlab-Event'].replace(' ', '_').lower()
            provider = self.gitlab

        body = await request.json()

        if event_type == 'ping':
            logger.info('Received ping event triggered by {0}'.format(body['hook']['url']))
            return Response(status=204)

        repo = provider.get_repo(body)
        global_event = self.is_global_event(event_type, repo, body)

        if global_event:
            pass

        if not (await self.has_repo(repo)) and not global_event:
            # Not a repository we know so accept the payload, return 200 but
            # discard the message
            logger.info('Message received for {0} but no such repository '
                        'is configured'.format(repo))
            return Response(status=204)

        token = await self.get_token(repo)
        if token is None and self.validation_enabled:
            # No token, no validation. Accept the payload since it's not their
            # fault that the user hasn't configured a token yet but log a
            # message about it and discard it.
            logger.info('Message received for {0} but no token '
                        'configured'.format(repo))
            return Response(status=204)

        if self.validation_enabled and not (await provider.valid_message(request, token)):
            ip = request.headers.get('X-Real-IP')
            if ip is None:
                logger.warning('Event received for {0} but could not validate it.'.format(repo))
            else:
                logger.warning('Event received for {0} from {1} but could not validate it.'.format(repo, ip))
            return Response(status=403)

        message = provider.create_message(body, event_type, repo)
        logger.debug('Prepared message: {0}'.format(message))

        # - if we have a message and is it not empty or None
        # - get all rooms for the repository we received the event for
        # - check if we should deliver this event
        # - join the room (this won't do anything if we're already joined)
        # - send the message
        if message and message is not None:
            for room_name in await self.get_routes(repo):
                events = await self.get_events(repo, room_name)
                logger.debug('Routes for room {0}: {1}'.format(room_name, events))
                if event_type in events or '*' in events:
                    await self.join_and_send(room_name, message)
            if global_event:
                gr = await self.load('global_route')
                if gr is not None:
                    await self.join_and_send(gr, message)
        return Response(status=204)

    async def join_and_send(self, room_name, message):
        await self.opsdroid.send(Message(message, target=room_name))

    def is_global_event(self, event_type, repo, body):
        return event_type in ['repository', 'membership', 'member', 'team_add', 'fork']

    async def validate_incoming(self, request: Request):
        """Validate the incoming request:

          * Check if the headers we need exist
          * Check if the payload decodes to something we expect
          * Check if it contains the repository
        """

        if request.content_type != 'application/json':
            logger.warning('ContentType is not json: {}'.format(request.content_type))
            return False
        for header in REQUIRED_HEADERS:
            if isinstance(header, tuple):
                if not any(request.headers.get(h) for h in header):
                    logger.warning('Missing (any of) headers: {}'.format(header))
                    return False
            else:
                if request.headers.get(header) is None:
                    logger.warning('Missing header: {}'.format(header))
                    return False

        try:
            body = await request.json()
        except ValueError:
            logger.warning('Request body is not json: {}'.format(request))
            return False

        if not isinstance(body, dict):
            logger.warning('Request body is not valid json: {}'.format(body))
            return False

        return True
