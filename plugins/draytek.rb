Plugin.define do
  name "DrayTek Vigor"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "DrayTek Vigor3900, Vigor2960, and Vigor300B devices are vulnerable to remote command execution."
  website "https://www.draytek.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Vigor Login Page<\/title>/i,  # Matching the error or contact warning
      :name => "DrayTek Vigor"
    },
  ]
end
