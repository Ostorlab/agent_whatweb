Plugin.define do
  name "ioBroker.lovelace"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the ioBroker.lovelace adapter, an ioBroker visualization that reuses the Home Assistant Lovelace frontend. The landing document carries the ioBroker title and application-name markers together with the home-assistant custom element. The adapter release is not present on the landing and WhatWeb does not fetch the package or /auth/providers at default aggression, so version extraction is a gap."
  website "https://github.com/ioBroker/ioBroker.lovelace"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*ioBroker\s*<\/title>.{0,65536}?<meta[^>]+(?:name|property)=[\"']application-name[\"'][^>]+content=[\"']ioBroker[\"'].{0,65536}?<home-assistant[\s>]/mi,
      :name => "ioBroker Lovelace dashboard title, application-name and Home Assistant element",
    },
  ]
end
