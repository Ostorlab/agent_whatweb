Plugin.define do
  name "Netgear-Router"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Netgear Router - From wireless routers and adapters to Layer 3 Managed Switches we have the networking equipment you need for your home or small business."
  website "http://www.netgear.com/products/"

  matches [
    {
      :search=>"headers[www-authenticate]",
      :regexp=>/^Basic realm="?[\s]*Netgear/,
    },
    {
      :model=>/^Basic realm="?[\s]*NETGEAR ([^"]+)[\s]*"?/,
      :regexp=>/^Basic realm="?[\s]*Netgear/,
    }
  ]
end

