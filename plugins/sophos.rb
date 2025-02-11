Plugin.define do
  name "Sophos"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Sophos defends organizations from inevitable cyberattacks with innovative, adaptive, AI-driven solutions and proven expertise."
  website "https://www.sophos.com/en-us/company"

  matches [
    {
      :search => "title",
      :regexp => /<title>Sophos<\/title>/,
      :name => "Sophos Title Tag"
    },
  ]
end