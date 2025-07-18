Plugin.define do
  name "Cisco ISE"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "Identifies Cisco Identity Services Engine (ISE), a network access control solution by Cisco."
  website "https://www.cisco.com/site/us/en/products/security/identity-services-engine/index.html"

  matches [
    {
      :search => "headers[set-cookie]",
      :regexp => /APPSESSIONID=/i,
      :name => "ISE Session Cookie"
    },
    {
      :search => "body",
      :regexp => /Cisco Identity Services Engine/i,
      :name => "Cisco ISE String in Body"
    }
  ]
end
