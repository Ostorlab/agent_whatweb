Plugin.define do
  name "Cisco ASA"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "Cisco ASA Software delivers enterprise-class security capabilities for the ASA security family in a variety of form factors."
  website "https://www.cisco.com/c/en/us/products/security/adaptive-security-appliance-asa-software/index.html"

  matches [
    {
      :search => "body",
      :regexp => /<img src="\/\+CSCOU\+\/csco_logo\.gif".*?SSL VPN Service/,
      :name => "Cisco ASA SSL VPN page with logo and service name"
    }
  ]
end
