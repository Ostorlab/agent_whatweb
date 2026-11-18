Plugin.define do
  name "Cisco Catalyst SD-WAN Manager"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Cisco Catalyst SD-WAN Manager (vManage), the management component of Cisco Catalyst SD-WAN."
  website "https://www.cisco.com/c/en/us/products/routers/sd-wan-manager/index.html"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*(?:Cisco\s+)?(?:Catalyst\s+)?(?:SD-WAN\s+Manager|vManage)\s*<\/title>/i,
      :name => "vManage login title",
    },
    {
      :search => "body",
      :regexp => /Cisco\s+(?:Catalyst\s+)?SD-WAN\s+Manager/i,
      :name => "Cisco SD-WAN Manager marker",
    },
    {
      :search => "body",
      :regexp => /Cisco\s+vManage/i,
      :name => "Cisco vManage marker",
    },
    {
      :search => "body",
      :regexp => /\bvManage\b/,
      :name => "vManage marker",
    },
  ]
end
