Plugin.define do
	name "pfSense"
	authors [
	  "Ostorlab",
	]
    version "0.1"
	description "pfSense is an open-source firewall and router software"
	website "https://www.pfsense.org/"

	matches [
		{:text => "<h4>Login to pfSense</h4>"},
		{:text => "<h4>Login to Netgate pfSense Plus</h4>"},
		{:text => "<script src=\"/js/pfSense.js"}
	]
  end

