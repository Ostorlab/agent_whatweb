Plugin.define do
  name "DELMIA Apriso"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "DELMIA Apriso is a manufacturing software platform that provides solutions for managing manufacturing operations."
  website "https://www.3ds.com/products-services/delmia/products/apriso/"

  matches [
    {
      :search => "body",
      :regexp => /\/Apriso\/Portal/,
      :name => "DELMIA Apriso Portal"
    },
  ]
end
