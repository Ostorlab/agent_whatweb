"""Unittests for mcp runner."""

from pytest_mock import plugin

from agent.mcp_server import mcp_runner


def testMCPRunner_whenRun_shouldCallPopenWithCorrectCommand(
    mocker: plugin.MockerFixture,
) -> None:
    """Test MCPRunner run method."""
    popen_mock = mocker.patch("subprocess.Popen")
    agent_version = "1.0.0"
    runner = mcp_runner.MCPRunner(
        agent_key="agent/ostorlab/whatweb_agent",
        agent_version=agent_version,
    )

    runner.run()

    expected_command = [
        "python3.14",
        mcp_runner.SERVER_PATH,
        "--agent-key",
        "agent/ostorlab/whatweb_agent",
        "--agent-version",
        "1.0.0",
    ]

    popen_mock.assert_called_once_with(
        expected_command,
    )
