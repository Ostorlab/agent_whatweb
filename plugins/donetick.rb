Plugin.define do
  name "Donetick"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Donetick, the self-hosted chore-tracking web application, from the product title and the startup-theme marker its own landing document carries. The landing exposes no release; the CVE rule reads /api/v1/resource itself, so version extraction is a gap."
  website "https://github.com/donetick/donetick"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Donetick\s*<\/title>)(?=.*donetick-theme-skin)/mi,
      :name => "Donetick title and startup-theme marker",
    },
  ]
end
