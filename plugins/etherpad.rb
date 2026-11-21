Plugin.define do
  name "Etherpad"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Etherpad, a real-time collaborative editor. The landing document carries the default Etherpad title, or the template's localization link when the title is customized. The release is not part of the landing response."
  website "https://etherpad.org"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*Etherpad\s*<\/title>/i,
      :name => "Etherpad landing title",
    },
    {
      :search => "body",
      :regexp => /<link[^>]+(?=[^>]*\brel=["']localizations["'])[^>]*\bhref=["']\/?locales\.json["']/i,
      :name => "Etherpad localization marker",
    },
  ]
end
