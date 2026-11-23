Plugin.define do
  name "ioBroker.lovelace"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the ioBroker.lovelace adapter, an ioBroker visualization that reuses the Home Assistant Lovelace frontend. The landing document carries the ioBroker title and application-name markers together with the home-assistant custom element; the adapter release is exposed on the network by /auth/providers and the adapter package, which WhatWeb does not request at default aggression."
  website "https://github.com/ioBroker/ioBroker.lovelace"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*ioBroker\s*<\/title>[\s\S]{0,65536}?<meta[^>]+(?:name|property)=[\"']application-name[\"'][^>]+content=[\"']ioBroker[\"'][\s\S]{0,65536}?<home-assistant[\s>]/i,
      :name => "ioBroker Lovelace dashboard title, application-name and Home Assistant element",
    },
  ]
end
