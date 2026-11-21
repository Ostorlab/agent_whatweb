Plugin.define do
  name "Dialoqbase"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Dialoqbase, a self-hosted chatbot platform. The landing document is the Vite single-page client; the server release is not in the landing response."
  website "https://github.com/n4ze3m/dialoqbase"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*Dialoqbase\s*<\/title>[\s\S]{0,2000}?<div\s+id=["']root["']/i,
      :name => "Dialoqbase SPA landing",
    },
  ]
end
