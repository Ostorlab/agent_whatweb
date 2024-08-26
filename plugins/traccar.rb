Plugin.define do
  name "Traccar GPS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Traccar is a free and open source GPS tracking server. "
  website "https://www.traccar.org/"

  matches [
    {
      :search => "title",
      :regexp => /<title>Traccar<\/title>/,
      :name => "Traccar Title Tag"
    },
  ]
end