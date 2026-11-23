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
      :version => /class="footer-versions".{0,300}?devpi-server-([0-9]+(?:\.[0-9]+)+)/mi,
      :name => "devpi-server footer version",
    },
  ]
end
