Plugin.define do
  name "LoadMaster Kemp"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Kemp LoadMaster is a load balancer and application delivery controller that optimizes web and application performance."
  website "https://kemptechnologies.com/"

  matches [
    {
      :search => "body",
      :regexp => /<img id="kemplogo" src="\/kemplogo\.png">/i,
      :name => "LoadMaster Kemp"
    },
  ]
end
