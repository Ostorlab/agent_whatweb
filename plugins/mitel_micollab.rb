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
      :regexp => /class=["']mitel_logo["'].*src=["'].*\/portal\/decorations\/layout\/loginPage\/images\/mitel_logo\.png["'].*alt=["']Mitel["']/i,
      :name => "Mitel MiCollab login page logo"
    },
    {
      :search => "body",
      :regexp => /MiCollab End User Portal/i,
      :name => "Mitel MiCollab End User Portal text"
    },
  ]
end
