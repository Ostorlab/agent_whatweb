Plugin.define do
  name "Zyxel Devices"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Zyxel provides a wide range of networking solutions, including Unified Security Gateways (USG) and USG FLEX series devices."
  website "https://www.zyxel.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>USG\d+<\/title>|<title>USG FLEX \d+<\/title>/i,
      :name => "Zyxel USG or USG FLEX Title Match"
    },
    {
      :search => "body",
      :regexp => /<title>.*Web-Based Configurator.*<\/title>/i,
      :name => "Zyxel Title Login Page"
    },
  ]
end
