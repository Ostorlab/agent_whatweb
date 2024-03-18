<h1 align="center">Agent Whatweb</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_whatweb">
<img src="https://img.shields.io/github/stars/ostorlab/agent_whatweb">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Whatweb is a web technology fingerprinter capable of detecting CMS, blogging platform, analytics pacakges, JS libraries, web servier and embeded devices._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_whatweb/blob/main/images/logo.png" alt="agent-whatweb" />
</p>

This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for the [Whatweb Fingerprinter](https://github.com/urbanadventurer/WhatWeb.git).

## Getting Started
To perform your first scan, simply run the following command.
```shell
oxo scan run --install --agent agent/ostorlab/whatweb domain-name tesla.com
```

This command will download and install `agent/ostorlab/whatweb`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Whatweb can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/whatweb
 ```

You can then run the agent with the following command:

```shell
oxo scan run --agent agent/ostorlab/whatweb domain-name tesla.com
```


### Build directly from the repository

 1. To build the whatweb agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_whatweb.git && cd agent_whatweb
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 1. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  oxo scan run --agent agent//whatweb domain-name tesla.com
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  oxo scan run --agent agent/[ORGANIZATION]/whatweb domain-name tesla.com
	  ```


## License
[Apache-2](./LICENSE)
