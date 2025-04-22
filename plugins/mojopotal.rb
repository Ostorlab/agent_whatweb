Plugin.define do
  name "mojoPortal"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "mojoPortal is a free, open-source CMS that allows users to build dynamic websites, blogs, and community portals."
  website "https://www.mojoportal.com"

  matches [
    {
      :search => "body",
      :regexp => /Powered by mojoPortal/i,
    },
  ]
end
