Plugin.define do
  name "PaloAltoNetworks PAN-OS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Palo Alto Networks PAN-OS is a next-generation firewall operating system that delivers advanced security features."
  website "https://www.paloaltonetworks.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>GlobalProtect Portal<\/title>/i,
      :name => "Palo Alto Networks PAN-OS GlobalProtect Portal Title"
    },
  ]
end
