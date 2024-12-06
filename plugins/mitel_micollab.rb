Plugin.define do
  name "Mitel MiCollab"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Mitel MiCollab is a collaboration software solution that provides unified communications and collaboration tools for businesses."
  website "https://www.mitel.com/products/applications/collaboration/micollab"

  matches [
    {
      :search => "body",
      :regexp => /class=.*mitel_logo\.png/i,
      :name => "Mitel MiCollab login page logo"
    },
    {
      :search => "body",
      :regexp => /MiCollab End User Portal/i,
      :name => "Mitel MiCollab End User Portal text"
    },
  ]
end
