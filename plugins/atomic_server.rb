Plugin.define do
  name "Atomic Server"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Atomic Server, an open-source headless CMS and real-time graph database. The landing document is the Atomic Data single-page client; the server release is exposed in the x-atomic-server-version response header on 0.41 and later."
  website "https://github.com/ontola/atomic-server"

  # The affected 0.39/0.40 releases expose no release marker in the landing
  # response; 0.41 and later add the release in x-atomic-server-version.
  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Atomic Data\s*<\/title>)(?=.*The easiest way to create, share and model Linked Atomic Data\.)(?=.*Meta tags and code added by Atomic-Server)/mi,
      :name => "Atomic Data landing title and server markers",
    },
    {
      :search => "headers[x-atomic-server-version]",
      :version => /([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)/,
      :name => "x-atomic-server-version header",
    },
  ]
end
