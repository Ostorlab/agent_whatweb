Plugin.define do
  name "Caldera Framework"
  authors [
    "ostorlab",
  ]
  version "0.1"
  description "Caldera™ is an adversary emulation platform designed to easily run autonomous breach-and-attack simulation exercises. It can also be used to run manual red-team engagements or automated incident response."
  website "https://caldera.mitre.org/"

  matches [
    {
      :search => "body",
      :regexp => /<title>\s*|\sCALDERA<\/title>/i,
      :name => "Caldera Framework Title Tag"
    }
  ]
end
