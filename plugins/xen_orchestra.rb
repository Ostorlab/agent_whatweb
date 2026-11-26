Plugin.define do
  name "Xen Orchestra"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Vates Xen Orchestra, the management interface for XCP-ng and XenServer, from the product title and the SPA container markers its own landing document carries. The landing exposes no release; the companion CVE rule reads the REST swagger document itself, so version extraction is a gap."
  website "https://xen-orchestra.com/"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Xen Orchestra\s*<\/title>)(?=.*(?:id=["']xo-app["']|assets\/loading\.svg|assets\/manifest\.webmanifest))/mi,
      :name => "Xen Orchestra title and SPA container marker",
    },
  ]
end
