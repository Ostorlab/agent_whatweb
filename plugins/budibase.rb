Plugin.define do
  name "Budibase"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Budibase, an open-source low-code application platform, from its builder landing document: the exact Budibase document title together with a /builder/ asset path. The landing carries no release, so version extraction is a gap and the CVE rule reads the public-settings endpoint itself."
  website "https://budibase.com"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Budibase\s*<\/title>)(?=.*\/builder\/)/mi,
      :name => "Budibase document title and builder asset path",
    },
  ]
end
