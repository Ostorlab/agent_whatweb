Plugin.define do
  name "PrestaShop lgcookieslaw"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the EU Cookie Law GDPR (Banner + Blocker) PrestaShop module (lgcookieslaw) from the landing document. The module renders its front CSS/JavaScript asset references on every shop page; the release is not part of that response."
  website "https://addons.prestashop.com/en/legal/8734-eu-cookie-law-gdpr-banner-blocker.html"

  matches [
    {
      :search => "body",
      :regexp => /(?:href|src)=["'](?!(?:https?:)?\/\/)[^"']*\/modules\/lgcookieslaw\/views\/(?:css\/front\.css|js\/front\.js)/i,
      :name => "lgcookieslaw front asset reference",
    },
    {
      :search => "body",
      :regexp => /lgcookieslaw_accepted_purposes|__lglaw/i,
      :name => "lgcookieslaw consent state",
    },
    {
      :search => "body",
      :version => /\/modules\/lgcookieslaw\/views\/(?:css\/front\.css|js\/front\.js)\?[^"' ]*?\bv=([0-9]+(?:\.[0-9]+){1,3})/i,
      :name => "lgcookieslaw asset query version",
    },
  ]
end
