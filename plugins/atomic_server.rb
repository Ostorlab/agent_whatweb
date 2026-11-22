Plugin.define do
  name "Atomic Server"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Atomic Server, an open-source headless CMS and real-time graph database. The landing document is the Atomic Data single-page client; the server release is exposed in the x-atomic-server-version response header on 0.41 and later."
  website "https://github.com/ontola/atomic-server"

  matches [
    {
      :search => "body",
      :regexp => /^(?=[\s\S]*<title[^>]*>\s*Atomic Data\s*<\/title>)(?=[\s\S]*The easiest way to create, share and model Linked Atomic Data\.)(?=[\s\S]*Meta tags and code added by Atomic-Server)/i,
      :name => "Atomic Data landing title and server markers",
    },
    {
      :search => "headers[x-atomic-server-version]",
      :version => /([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)/,
      :name => "x-atomic-server-version header",
    },
  ]
end
