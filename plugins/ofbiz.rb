Plugin.define do
	name "ofbiz"
	authors [
	  "Ostorlab",
	]
	version "0.1"
	description "OFBiz is an open-source enterprise resource planning (ERP) system."
	website "https://ofbiz.apache.org/"

	matches [
	  {
        :search => "headers[Set-Cookie]",
        :regexp => /OFBiz\.Visitor=/,
        :name => "OFBiz.Visitor cookie"
       },
	]
  end

