Plugin.define do
  name "Cisco SSM On-Prem"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Cisco Smart Software Manager On-Prem (SSM On-Prem) is a Smart Licensing solution that enables customers to administer products and licenses on their premises."
  website "https://www.cisco.com/"

  matches [
    {
      :search => "head",
      :regexp => /<title>On-Prem License Workspace<\/title>/,
      :name => "On-Prem License Workspace Generator Title Tag"
    },
  ]
end