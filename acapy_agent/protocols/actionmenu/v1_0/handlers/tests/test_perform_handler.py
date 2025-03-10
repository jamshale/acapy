from unittest import IsolatedAsyncioTestCase

from acapy_agent.tests import mock

from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......utils.testing import create_test_profile
from .. import perform_handler as handler


class TestPerformHandler(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.context = RequestContext.test_context(await create_test_profile())

    async def test_called(self):
        self.menu_service = mock.MagicMock(handler.BaseMenuService, autospec=True)
        self.context.injector.bind_instance(handler.BaseMenuService, self.menu_service)

        self.context.connection_record = mock.MagicMock()
        self.context.connection_record.connection_id = "dummy"
        self.context.connection_ready = True

        responder = MockResponder()
        self.context.message = handler.Perform()
        self.menu_service.perform_menu_action = mock.CoroutineMock(return_value="perform")

        handler_inst = handler.PerformHandler()
        await handler_inst.handle(self.context, responder)

        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "perform"
        assert target == {}

    async def test_called_no_active_menu(self):
        self.menu_service = mock.MagicMock(handler.BaseMenuService, autospec=True)
        self.context.injector.bind_instance(handler.BaseMenuService, self.menu_service)

        self.context.connection_record = mock.MagicMock()
        self.context.connection_record.connection_id = "dummy"
        self.context.connection_ready = True

        responder = MockResponder()
        self.context.message = handler.Perform()
        self.menu_service.perform_menu_action = mock.CoroutineMock(return_value=None)

        handler_inst = handler.PerformHandler()
        await handler_inst.handle(self.context, responder)

        messages = responder.messages
        assert not messages
