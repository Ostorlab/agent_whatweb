Plugin.define do
  name "SiYuan"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies SiYuan, a local-first personal knowledge management system. The landing redirects to the desktop single-page application, whose SiYuan title and b3 dialog/app-loading or desktop-bundle markers are product-specific; the release is exposed only by the public /api/system/version API, which WhatWeb does not request at default aggression; a directly exposed kernel that answers the landing with a 401 JSON document is not identified."
  website "https://b3log.org/siyuan"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*SiYuan\s*<\/title>[\s\S]{0,65536}?(?:b3-dialog\s+b3-dialog--open\s+app-loading|stage\/build\/desktop\/main\.)/i,
      :name => "SiYuan desktop SPA title and b3 UI markers",
    },
  ]
end
