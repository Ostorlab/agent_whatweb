Plugin.define do
  name "HILLSTONE NETWORKS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Hillstone Networks' Enterprise Network Security and Risk Management solutions provide visibility, intelligence, and protection to ensure enterprises can comprehensively see, thoroughly understand, and rapidly act against cyber-threats."
  website "https://www.hillstonenet.com/"

  matches [
    {
      :search => "title",
      :regexp => /<title>HILLSTONE NETWORKS<\/title>/,
      :name => "HILLSTONE NETWORKS Title Tag"
    },
  ]
end