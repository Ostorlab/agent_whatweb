Plugin.define do
  name "vigorconnect"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Local Network Management Software for DrayTek Devices"
  website "https://www.draytek.com/products/vigorconnect/"

  matches [
    {
      :search => "body",
      :regexp => /vigorconnect|VigorConnect/,
      :name => "vigorconnect"
    },
  ]
end