Plugin.define do
  name "Sprout Track"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Sprout Track, a self-hosted baby-tracking web application. The landing document carries both the product title and its baby-tracking meta description; the release is not part of the landing response."
  website "https://www.sprout-track.com"

  matches [
    {
      :search => "body",
      :regexp => /^(?=[\s\S]*<title[^>]*>\s*Sprout Track\s*<\/title>)(?=[\s\S]*<meta(?=[^>]*\bname=["']description["'])(?=[^>]*\bcontent=["'][^"']*Track your baby)[^>]*>)/i,
      :name => "Sprout Track title and baby-tracking description",
    },
  ]
end
