Plugin.define do
  name "Devpi"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies devpi, a PyPI-compatible package index server with the devpi-web user interface. The landing document carries the devpi-server release in its footer."
  website "https://github.com/devpi/devpi"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*devpi\s*<\/title>/i,
      :name => "devpi landing title",
    },
    {
      :search => "body",
      :version => /devpi-server-([0-9]+(?:\.[0-9]+)+)/i,
      :name => "devpi-server footer version",
    },
  ]
end
