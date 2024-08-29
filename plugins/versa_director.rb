Plugin.define do
  name "Versa Director"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Detects the presence of Versa Director, a network and security management solution by Versa Networks."
  website "https://www.versa-networks.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Versa Director/i,
      :name => "HTML Title Tag with Versa Director"
    }
  ]
end
