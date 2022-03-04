"""WhatWeb Agent : Agent responsible for identifying a website."""

import logging
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

import agent.whatweb.whatweb as wbb

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


class WhatWebAgent(agent.Agent):
    """Agent responsible for identifying a website."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        """Inits the whatweb agent."""
        super().__init__(agent_definition, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Starts a tsunami scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime."""

        target = wbb.Target(
            address=message.data['url'])
        with wbb.WhatWeb() as whatweb_scanner:
            scan_result = whatweb_scanner.scan(target=target)
            logger.info('Scan finished Number of finding %s', len(scan_result))

        del message
        logger.info('processing message')
        self.emit('v3.healthcheck.ping', {'body': 'Hello World!'})
# if __name__ == '__main__':
#     logger.info('WhatWeb agent starting ...')
#     WhatWebAgent.main()


# testing code: to be removed
if __name__ == '__main__':
    agent_definition = agent_definitions.AgentDefinition(
        name='whatweb',
        out_selectors=['v3.report.event.vulnerability'],
        in_selectors=[]
    )
    agent_settings = runtime_definitions.AgentSettings(
        key='whatweb'
    )
    whatWebAgent = WhatWebAgent(agent_definition, agent_settings)
    data = {
        'url': 'ostorlab.co'
    }

    target = wbb.Target(address=data['url'])
    with wbb.WhatWeb() as whatweb_scanner:
        print('the main')
        scan_result = whatweb_scanner.scan(target=target)
        print('Res ', scan_result)
