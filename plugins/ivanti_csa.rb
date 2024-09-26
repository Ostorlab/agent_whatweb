Plugin.define do
  name "Ivanti CSA"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "The Ivanti Cloud Services Appliance (CSA) is an Internet appliance that provides secure communication and functionality over the Internet."
  website "https://www.ivanti.com/"

  matches [
    {
      :search => "title",
      :regexp => /<title>Ivanti\(R\) Cloud Services Appliance<\/title>/,
      :name => "Ivanti CSA Title Tag"
    },
  ]
end