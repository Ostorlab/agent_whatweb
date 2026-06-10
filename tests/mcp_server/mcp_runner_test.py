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
        service_name="whatweb",
        agent_key="agent/ostorlab/whatweb_agent",
        hostname="7b3572cd4d39",
        host_hostname="m5",
        agent_version=agent_version,
        logging_credentials=logging_credentials,
    )

    runner.run()

    expected_command = [
        "python3.14",
        mcp_runner.SERVER_PATH,
        "--universe",
        "test_universe",
        "--service-name",
        "whatweb",
        "--agent-key",
        "agent/ostorlab/whatweb_agent",
        "--hostname",
        "7b3572cd4d39",
        "--host-hostname",
        "m5",
        "--agent-version",
        "1.0.0",
        "--logging-credentials",
        "test_credentials",
    ]

    popen_mock.assert_called_once_with(
        expected_command,
    )
