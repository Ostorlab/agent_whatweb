"""Unittests for mcp runner."""

from pytest_mock import plugin

from agent.mcp_server import mcp_runner


def testMCPRunner_whenRun_shouldCallPopenWithCorrectCommand(
    mocker: plugin.MockerFixture,
) -> None:
    """Test MCPRunner run method."""
    popen_mock = mocker.patch("subprocess.Popen")
    universe = "test_universe"
    agent_version = "1.0.0"
    logging_credentials = "test_credentials"
    runner = mcp_runner.MCPRunner(
        universe=universe,
        agent_version=agent_version,
        logging_credentials=logging_credentials,
    )

    runner.run()

    expected_command = [
        "python3.11",
        mcp_runner.SERVER_PATH,
        agent_version,
        universe,
        logging_credentials,
    ]
    popen_mock.assert_called_once_with(expected_command)
