Plugin.define do
	name "Github Enterprise Server"
	authors [
	  "Ostorlab",
	]
    version "0.1"
	description "GitHub Enterprise Server is a self-hosted version of the GitHub platform"
	website "https://docs.github.com/en/enterprise-server/"

	matches [
        {
            :regexp => /GitHub\sEnterprise\sServer\s\d+\.\d+\.\d+/,
            :name => "Github server enterprise version"
        }
	]
  end