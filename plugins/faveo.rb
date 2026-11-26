##
# Faveo Helpdesk fingerprint for the asset inventory and vulnerable-component
# matching.
#
# Faveo Helpdesk (Community) renders its guest portal with a fixed footer that
# credits the product: "Powered by <a href="https://www.faveohelpdesk.com/"
# ...>Faveo</a>". That footer is part of the shipped client layout and is
# present on the public landing page with or without an authenticated session,
# so WhatWeb reaches it with its single default request.
#
# The landing document does not carry the release; the `settings_system.version`
# value is a database field that the client layout does not render. The
# Asteroid rule for CVE-2026-69697 therefore reads the anonymous
# `/api/v1/helpdesk/url` behaviour itself, and this plugin records the product
# without a version rather than inferring one.
##
Plugin.define do
  name "Faveo Helpdesk"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Faveo Helpdesk from the product footer on its public guest-portal landing page."
  website "https://www.faveohelpdesk.com/"

  matches [
    {
      :search => "body",
      :regexp => /Powered by\s*<a href="https:\/\/www\.faveohelpdesk\.com\/"[^>]{0,200}>\s*Faveo\s*<\/a>/i,
      :name => "Faveo powered-by footer",
    },
  ]
end
