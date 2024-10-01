Plugin.define do
  name "D-Link"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "D-Link is a wireless router providing internet access and networking capabilities."
  website "http://www.dlink.com/"

  matches [
    {
      :search => "body",
      :regexp => /<a href="http:\/\/www.dlink.com\/us\/en\/support">/,
      :name => "D-Link Support Link"
    },
  ]
end
