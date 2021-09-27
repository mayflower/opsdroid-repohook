import hashlib
import hmac
import os.path

from aiohttp.web import Request
from jinja2 import Environment, FileSystemLoader

GITHUB_EVENTS = ['commit_comment', 'create', 'delete', 'deployment',
                 'deployment_status', 'fork', 'gollum', 'issue_comment',
                 'issues', 'member', 'page_build', 'public',
                 'pull_request_review_comment', 'pull_request', 'push',
                 'release', 'status', 'team_add', 'watch', '*']
GITLAB_EVENTS = ['push_hook', 'tag_push_hook', 'issue_hook', 'note_hook', 'merge_request_hook']
SUPPORTED_EVENTS = GITHUB_EVENTS + GITLAB_EVENTS
DEFAULT_EVENTS = ['commit_comment', 'issue_comment', 'issues', 'pull_request_review_comment',
                  'pull_request', 'push', 'push_hook', 'tag_push_hook', 'issue_hook',
                  'note_hook', 'merge_request_hook']


class CommonGitWebProvider(object):
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
            trim_blocks=True,
            keep_trailing_newline=False,
            autoescape=True,
        )

    def create_message(self, body, event_type, repo):
        """
        Dispatch the message. Check explicitly with hasattr first. When
        using a try/catch with AttributeError errors in the
        message_function which result in an AttributeError would cause
        us to call msg_generic, which is not what we want.
        """
        message_function = 'msg_{0}'.format(event_type)
        if hasattr(self, message_function):
            message = getattr(self, message_function)(body, repo)
        else:
            message = self.msg_generic(body, repo, event_type)
        return message

    def render_template(self, template='generic', **kwargs):
        kwargs['repo_name'] = kwargs.get('repo_name') or self.name
        tpl = self.env.get_template(f"{template}.html")
        return tpl.render(**kwargs)

    def msg_generic(self, body, repo, event_type):
        return self.render_template(
            template='generic', body=body, repo=repo, event_type=event_type)


class GithubHandlers(CommonGitWebProvider):
    name = 'Github'

    @staticmethod
    async def valid_message(request: Request, token):
        """Validate the signature of the incoming payload.

        The header received from Github is in the form of algorithm=hash.
        """
        # TODO: Fix GitLab token validation:
        #       https://docs.gitlab.com/ce/web_hooks/web_hooks.html#secret-token
        signature = request.headers.get('X-Hub-Signature')

        if signature is None:
            return False

        try:
            alg, sig = signature.split('=')
        except ValueError:
            return False

        if alg != 'sha1':
            return False

        message = await request.read()
        mac = hmac.new(token.encode(), msg=message, digestmod=hashlib.sha1).hexdigest()
        return hmac.compare_digest(mac, sig)

    def get_repo(self, body):
        return body['repository']['full_name']

    def msg_issues(self, body, repo):
        return self.render_template(
            template='issues', body=body, repo=repo,
            action=body['action'],
            number=body['issue']['number'],
            title=body['issue']['title'],
            user=body['issue']['user']['login'],
            url=body['issue']['url'],
            is_assigned=body['issue']['assignee'],
            assignee=body['issue']['assignee']['login'] if body['issue']['assignee'] else None,
            text=body['issue']['body']
        )

    def msg_pull_request(self, body, repo):
        action = body['action']
        user = body['pull_request']['user']['login']
        if action == 'closed' and body['pull_request']['merged']:
            user = body['pull_request']['merged_by']['login']
            action = 'merged'
        if action == 'synchronize':
            action = 'updated'

        return self.render_template(
            template='pull_request', body=body, repo=repo,
            action=action, user=user,
            number=body['pull_request']['number'],
            url=body['pull_request']['html_url'],
            title=body['pull_request']['title'],
            text=body['pull_request']['body']
        )

    def msg_pull_request_review(self, body, repo):
        return self.render_template(
            template='pull_request_review', body=body, repo=repo,
            user=body['review']['user']['login'],
            pr=body['pull_request']['number'],
            url=body['pull_request']['html_url'],
            state='requested changes on' if body['review']['state'] == 'changes_requested' else body['review']['state'],
        )

    def msg_pull_request_review_comment(self, body, repo):
        return self.render_template(
            template='pull_request_review_comment', body=body, repo=repo,
            action=body['action'],
            user=body['comment']['user']['login'],
            url=body['comment']['html_url'],
            pr=body['pull_request']['number'],
            text=body['comment']['body']
        )

    def msg_push(self, body, repo):
        if body['created']:
            action = 'created'
        elif body['deleted']:
            action = 'deleted'
        elif body['forced']:
            action = 'force-pushed'
        else:
            action = 'pushed'
        return self.render_template(
            template='push', body=body, repo=repo,
            user=body['pusher']['name'],
            commits=len(body['commits']),
            branch=body['ref'].split('/')[-1],
            url=body['compare'],
            action=action,
        )

    def msg_status(*args):
        """Status events are crazy and free form. There's no sane, consistent
        or logical way to deal with them."""
        return None

    def msg_issue_comment(self, body, repo):
        return self.render_template(
            template='issue_comment', body=body, repo=repo,
            action=body['action'],
            user=body['comment']['user']['login'],
            number=body['issue']['number'],
            title=body['issue']['title'],
            url=body['issue']['html_url'],
            text=body['comment']['body']
        )

    def msg_commit_comment(self, body, repo):
        return self.render_template(
            template='commit_comment', body=body, repo=repo,
            user=body['comment']['user']['login'],
            url=body['comment']['html_url'],
            line=body['comment']['line'],
            sha=body['comment']['commit_id'],
            text=body['comment']['body']
        )

    def msg_repository(self, body, repo):
        return self.render_template(
            template='repository', body=body, repo=repo,
            action=body['action'],
            user=body['sender']['login']
        )


class GitLabHandlers(CommonGitWebProvider):
    name = 'GitLab'

    @staticmethod
    async def valid_message(request: Request, token):
        """Validate the signature of the incoming payload.

        The header received from GitLab is in the form of algorithm=hash.
        # TODO: Fix GitLab token validation:
        #       https://docs.gitlab.com/ce/web_hooks/web_hooks.html#secret-token
        """
        signature = request.headers.get('X-Gitlab-Token')
        return True

    def get_repo(self, body):
        if 'project' in body:
            return body['project']['path_with_namespace']
        else:
            return body['project_name'].replace(' ', '')

    def map_event_type(self, event_type):
        return {
            'push_hook': 'push',
            'issue_hook': 'issue',
            'note_hook': 'comment',
            'merge_request_hook': 'pull_request',
        }.get(event_type, event_type)

    def create_message(self, body, event_type, repo):
        mapped_event_type = self.map_event_type(event_type)
        return super(GitLabHandlers, self).create_message(body, mapped_event_type, repo)

    def msg_push(self, body, repo):
        if body['commits']:
            url = body['project']['web_url'] + '/compare/' + body['before'][:8] + '...' + body['after'][:8]
            action = "pushed"
            commit_messages = [
                dict(msg=c['message'], hash=c['id'][:8],
                     url=c['url']) for c in body['commits']
            ]
        else:
            if body['before'][:8] == '00000000':
                action = 'created'
            if body['after'][:8] == '00000000':
                action = 'deleted'
            url = body['project']['web_url']
            commit_messages = []

        return self.render_template(
            template='push', body=body, repo=repo,
            user=body['user_name'],
            commits=len(body['commits']),
            branch='/'.join(body['ref'].split('/')[2:]),
            url=url,
            commit_messages=commit_messages,
            action=action
        )

    def msg_issue(self, body, repo):
        action = {'reopen': 'reopened', 'close': 'closed', 'open': 'opened'}.get(body['object_attributes']['action'])
        if action:
            return self.render_template(
                template='issues', body=body, repo=repo,
                action=action,
                title=body['object_attributes']['title'],
                user=body['user']['name'],
                url=body['object_attributes']['url'],
                text=body['object_attributes']['description']
            )

    def msg_comment(self, body, repo):
        noteable = body['object_attributes']['noteable_type'].lower()
        if noteable == "issue":
            return self.render_template(
                template='issue_comment', body=body, repo=repo,
                user=body['user']['name'],
                url=body['object_attributes']['url'],
                action='created',
                title=body['issue']['title'],
                text=body['object_attributes']['note']
            )
        elif noteable == "commit":
            return self.render_template(
                template='commit_comment', body=body, repo=repo,
                user=body['user']['name'],
                url=body['object_attributes']['url'],
                line=None,
                text=body['object_attributes']['note']
            )
        elif noteable == "mergerequest":
            return self.render_template(
                template='pull_request_review_comment', body=body, repo=repo,
                user=body['user']['name'],
                url=body['object_attributes']['url'],
                action='created',
                text=body['object_attributes']['note'],
                pr=body['merge_request']['iid'],
            )

    def msg_pull_request(self, body, repo):
        action = body['object_attributes']['action']
        user = body['user']['name']
        if action == 'open':
            action = 'opened'
        if action == 'merge':
            action = 'merged'

        return self.render_template(
            template='pull_request', body=body, repo=repo,
            action=action, user=user,
            number=body['object_attributes']['iid'],
            url=body['object_attributes']['url'],
            text=body['object_attributes']['description'],
            title=body['object_attributes']['title']
        )

    def msg_pipeline_hook(self, body, repo):
        before = body['object_attributes']['before_sha'][:8]
        after = body['object_attributes']['sha'][:8]
        url = body['project']['web_url'] + '/compare/' + before + '...' + after
        return self.render_template(
            template='pipeline', body=body, repo=repo,
            status=body['object_attributes']['status'],
            user=body['user']['name'],
            branch=body['object_attributes']['ref'],
            url=url
        )

    def msg_build_hook(self, body, repo):
        if body['build_status'] != 'failed':
            return None

        return self.render_template(
            template='build', body=body, repo=repo,
            status=body['build_status'],
            name=body['build_name'],
            stage=body['build_stage'],
            user=body['user']['name'],
            branch=body['ref']
        )
