Plugin.define do
  name "ArangoDB"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies ArangoDB, a multi-model database with an HTTP API and the Aardvark web interface. The landing document is the web interface and does not expose the release; the version endpoint requires authentication on a default deployment."
  website "https://www.arangodb.com/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /\AArangoDB\b/i,
      :name => "ArangoDB Server Header",
    },
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*ArangoDB Web Interface\s*<\/title>/i,
      :name => "ArangoDB Web Interface title",
    },
  ]
end
