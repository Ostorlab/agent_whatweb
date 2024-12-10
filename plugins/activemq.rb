Plugin.define do
  name "Apache ActiveMQ"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Apache ActiveMQ is an open-source message broker written in Java that supports multiple messaging protocols."
  website "https://activemq.apache.org/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Apache\s+ActiveMQ<\/title>/i,
      :name => "Apache ActiveMQ Title Match"
    },
  ]
end
