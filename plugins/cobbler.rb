Plugin.define do
  name "Cobbler"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Cobbler is a Linux installation server that allows for rapid setup of network installation environments."
  website "https://cobbler.github.io/"

  matches [
    {
      :search => "body",
      :regexp => /"tagline"\s*:\s*"You Know, for Search"/,
      :name => "Tagline in API Response"
    },
    {
      :search => "body",
      :regexp => /<Key>cobbler_api<\/Key>/,
      :name => "Cobbler API Key Tag in Response"
    },
  ]
end
