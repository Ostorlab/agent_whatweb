Plugin.define do
  name "Daptin"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Daptin, an open-source headless CMS and JSON:API platform. The landing document is the Shadcn admin dashboard; the release is not present in it."
  website "https://github.com/daptin/daptin"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*Daptin Admin\s*<\/title>/i,
      :name => "Daptin admin title",
    },
  ]
end
