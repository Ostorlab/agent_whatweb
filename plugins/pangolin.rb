Plugin.define do
  name "Pangolin"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Pangolin, the self-hosted identity-aware reverse proxy, from the product name in its authentication page title and the pangolin.net link those pages carry. The authentication pages expose no release, so version extraction is a gap."
  website "https://github.com/fosrl/pangolin"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>[^<]*-\s*Pangolin\s*<\/title>)(?=.*https:\/\/pangolin\.net\/)/mi,
      :name => "Pangolin auth page title and product link",
    },
  ]
end
