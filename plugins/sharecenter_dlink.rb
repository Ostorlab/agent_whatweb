Plugin.define do
  name "D-Link DNS ShareCenter"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "This ShareCenter™ Cloud Storage device enables you to share documents and media content such as photos, music and videos on a home network or over the Internet."
  website "https://www.dlink.com/"

  matches [
    {
      :search => "body",
      :regexp => /In order to access the ShareCenter/,
      :name => "ShareCenter body Tag"
    },
  ]
end