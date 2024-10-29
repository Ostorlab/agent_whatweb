Plugin.define do
  name "RAVPN"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "A remote access virtual private network (VPN) enables users to connect to a private network remotely using a VPN."
  website "https://www.cisco.com/c/en/us/td/docs/security/firepower/623/fdm/fptd-fdm-config-guide-623/fptd-fdm-ravpn.html"

  matches [
    {
      :search => "body",
      :regexp => /<option value=.+?RAVPN/,
      :name => "RAVPN is mentioned in the body of the login page"
    }
  ]
end