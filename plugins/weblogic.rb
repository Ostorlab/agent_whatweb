Plugin.define do
	name "weblogic"
	authors [
	  "Ostorlab",
	]
	version "0.1"
	description "WebLogic is an Application Server that runs on a middle tier, between back-end databases and related applications and browser-based thin clients. WebLogic Server mediates the exchange of requests from the client tier with responses from the back-end tier."
	website "https://www.oracle.com/java/weblogic/"

	matches [
	  {
        :search => "headers[Server]",
        :regexp => /WebLogic Server=/,
        :name => "WebLogic Server Header tag"
       },
	]
  end

