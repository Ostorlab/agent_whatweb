Plugin.define do
  name "Craft CMS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Craft CMS is a flexible, user-friendly CMS for creating custom digital experiences on the web."
  website "https://craftcms.com/"

  matches [
    {
      :search => "headers[x-powered-by]",
      :regexp => /Craft CMS/,
      :name => "X-Powered-By header contains Craft CMS"
    },
    {
      :search => "headers[set-cookie]",
      :regexp => /(Craft|CRAFT)/,
      :name => "Set-Cookie header contains Craft or CRAFT"
    },
    {
      :search => "body",
      :regexp => /CRAFT_CSRF_TOKEN/i,
      :name => "Body contains CRAFT_CSRF_TOKEN"
    },
  ]
end
