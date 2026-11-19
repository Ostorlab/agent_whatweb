Plugin.define do
  name "GreaterWMS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies GreaterWMS, an open-source warehouse management system with a Quasar frontend and a Django backend."
  website "https://github.com/GreaterWMS/GreaterWMS"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*GreaterWMS--Open Source Warehouse Management System\s*<\/title>/i,
      :name => "GreaterWMS landing title",
    },
  ]
end
