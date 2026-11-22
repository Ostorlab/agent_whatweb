Plugin.define do
  name "Wavelog"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Wavelog, web-based amateur radio logging software. The landing redirects to the login document, whose title suffix and Wavelog footer/version-dialog asset are product-specific; the release is not part of the login response."
  website "https://www.wavelog.org"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>[^<]*-\s*Wavelog\s*<\/title>[\s\S]{0,100000}?(?:To connect your radio to Wavelog|www\.github\.com\/wavelog\/wavelog|assets\/js\/sections\/version_dialog\.js)/i,
      :name => "Wavelog login title and footer",
    },
  ]
end
