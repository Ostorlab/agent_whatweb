Plugin.define do
  name "Siemens"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Detects the Siemens Support Portal based on specific HTML structure in the page."
  website "https://support.industry.siemens.com/"

  matches [
    {
      :search => "body",
      :regexp => /<div class="logo">\s*<a href="http:\/\/support\.industry\.siemens\.com\/" target="_blank"><\/a>\s*<\/div>/i,
      :name => "Siemens Support Portal Logo Link"
    },
  ]
end
