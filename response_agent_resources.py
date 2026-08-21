"""Import bridge for tests/library imports of the Response agent.

Running ``scripts/response_agent.py`` directly resolves its sibling module normally.
When the agent is imported as ``scripts.response_agent`` (for qualification tests),
the repository root is on ``sys.path`` instead. Re-export the same implementation
here so both invocation modes exercise one source file.
"""

from scripts.response_agent_resources import *  # noqa: F401,F403
