Plugin.define do
  name "Cleo Products"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Cleo provides enterprise data integration solutions, including VLTrader, Harmony, and LexiCom for secure and scalable data exchanges."
  website "https://www.cleo.com/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /Cleo (VLTrader|Harmony|LexiCom)\/[\d.]+/i,
      :name => "Cleo Products Server Header with Version"
    },
  ]
end
