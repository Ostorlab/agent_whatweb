Plugin.define do
  name "Cyberoam"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Cyberoam Technologies, a Sophos subsidiary, is a global network security appliances provider, with presence in more than 125 countries."
  website "https://www.sophos.com/en-us/products/next-gen-firewall"

  matches [
    {
      :search => "body",
      :regexp => /<title>Cyberoam<\/title>/i,
      :name => "Cyberoam Title Match"
    },
  ]
end
