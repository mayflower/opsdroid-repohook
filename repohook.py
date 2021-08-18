from aiohttp.web import Request
from opsdroid.events import Message
from opsdroid.matchers import match_webhook
from opsdroid.skill import Skill


class HelloSkill(Skill):
    @match_webhook('test')
    async def hello(self, event: Request):
        await self.opsdroid.send(Message(str('Oy there')))
