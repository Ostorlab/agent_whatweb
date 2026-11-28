##
# Apache Roller fingerprint for the asset inventory and vulnerable-component
# matching.
#
# Roller serves its site front page and setup page with the product's own UI
# asset paths (`/roller-ui/styles/roller.css`, `/roller-ui/menu.rol`) and the
# `Apache Roller`/`Roller Site` product marker. The installed site front page
# carries the release in its footer:
#
#   Powered by <a href="http://roller.apache.org">Apache Roller</a> 6.1.5
#
# The release is extracted only from that footer; the setup page carries no
# release. The Asteroid CVE-2026-129448 rule reads the same landing and then
# exercises the XML-RPC servlet; this plugin performs no extra request.
#
# WhatWeb precompiles the :version regexp as the match regexp, so that single
# expression must capture the release on its own. The identity match is kept
# separate so a setup page without a release is still fingerprinted.
##
Plugin.define do
  name "Apache Roller"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Apache Roller, the Java weblog server, from its UI asset paths and front-page or setup-page product marker. Extracts the release when the installed front page advertises it."
  website "https://roller.apache.org/"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*(?:roller-ui\/styles\/roller\.css|roller-ui\/menu\.rol|roller-ui\/login|theme\/scripts\/roller\.js))(?=.*(?:Apache Roller|Roller initial setup|Roller Site|Welcome to Roller!))/mi,
      :name => "Apache Roller UI asset and product marker",
    },
    {
      :search => "body",
      :version => /Powered by\s*(?:<[^>]+>\s*)*Apache Roller\s*(?:<\/a>)?\s*v?([0-9]+(?:\.[0-9]+)+)/mi,
      :name => "Apache Roller front-page footer version",
    },
  ]
end
