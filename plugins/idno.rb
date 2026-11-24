Plugin.define do
  name "Idno"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Idno (formerly Known), the open-source social publishing platform, from the product's own powered-by response header and the generator meta tag its landing document carries. The landing does not expose a release; the X-Idno-Build-Fingerprint header is an opaque build hash, so version extraction is a gap."
  website "https://idno.co"

  matches [
    {
      :search => "headers[x-powered-by]",
      :regexp => /https?:\/\/idno\.co\/?/i,
      :name => "Idno powered-by header",
    },
    {
      :search => "body",
      :regexp => /<meta\s+name=["']generator["']\s+content=["']Idno\s+https?:\/\/idno\.co["']/i,
      :name => "Idno generator meta",
    },
  ]
end
