Plugin.define do
  name "devpi-web"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the devpi-web user interface and its release from the footer of a devpi landing document."
  website "https://github.com/devpi/devpi"

  matches [
    {
      :search => "body",
      :version => /devpi-web-([0-9]+(?:\.[0-9]+)+)/i,
      :name => "devpi-web footer version",
    },
  ]
end
