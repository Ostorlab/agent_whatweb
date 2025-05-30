Plugin.define do
  name "Cisco IOS XE WLC"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "Cisco IOS XE Software for Wireless LAN Controllers (WLCs) provides centralized management and control of wireless access points in enterprise networks. Vulnerable versions contain CVE-2025-20188, a critical arbitrary file upload vulnerability in the Out-of-Band AP Image Download feature."
  website "https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html"

  matches [
    {
      :search => "headers[server]",
      :regexp => /openresty/i,
      :name => "OpenResty Server Header"
    },
    {
      :search => "body",
      :regexp => /Cisco Systems/i,
      :name => "Cisco Systems in Body"
    }
  ]
end