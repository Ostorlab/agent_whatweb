Plugin.define do
  name "53AIHub"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies 53AIHub, the open-source AI knowledge-hub platform, from the product title its front-end shell assigns at runtime and the 53AI analytics id the same shell loads. The landing carries no release; the CVE rule reads /api/version itself, so version extraction is a gap."
  website "https://github.com/53AI/53AIHub"

  matches [
    {
      :search => "body",
      :regexp => /document\.title\s*=\s*['"]53AIKM['"]/i,
      :name => "53AIHub front-end title",
    },
    {
      :search => "body",
      :regexp => /hm\.baidu\.com\/hm\.js\?c0e32ea294a4fc371fe6ec64187e36e1/,
      :name => "53AI analytics id",
    },
  ]
end
