Plugin.define do
  name "SonicWall SSL VPN"
  authors [
    "Assistant",
  ]
  version "0.1"
  description "SonicWall SSL VPN provides secure remote access to corporate resources. It's part of SonicWall's network security product line."
  website "https://www.sonicwall.com/"

  matches [
    {
      :search => "body",
      :regexp => /<div id=sslvpn-portal>/i,
      :name => "SonicWall SSL VPN Portal Container"
    },
    {
      :search => "body",
      :regexp => /\/sonicui\/.*\/sslvpn-portal\//i,
      :name => "SonicWall SSL VPN Resource Path"
    }
  ]
end