Plugin.define do
  name "openIMIS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the openIMIS frontend from its exact landing title. The openIMIS backend API serves no product-identifying landing response; the companion report-module CVE rule reads the API route itself, so version extraction is a gap."
  website "https://openimis.org/"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*openIMIS\s*<\/title>/i,
      :name => "openIMIS landing title",
    },
  ]
end
