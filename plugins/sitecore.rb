Plugin.define do
  name "Sitecore"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Sitecore is a digital experience platform that combines content management, commerce, and customer insights."
  website "https://www.sitecore.com/"

  matches [
    {
      :search => "head",
      :regexp => /<title>\s*Welcome to Sitecore\s*<\/title>/,
      :name => "Sitecore Title Tag"
    },
    {
      :search => "body",
      :regexp => /<div id="Footer"><hr class="divider"\/>&#169; 2024 Sitecore<\/div>/,
      :name => "Sitecore Footer"
    },
  ]
end
