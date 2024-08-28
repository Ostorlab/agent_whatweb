Plugin.define do
  name "SonicWALL SonicOS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "SonicWall SonicOS and SonicOSX (SonicOS/X) runs on SonicWall firewalls and provides the web management interface, API and the Command Line Interface for firewall configuration."
  website "https://www.sonicwall.com/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /SonicWALL/i,
      :name => "SonicWALL SonicOS Title Tag"
    },
  ]
end