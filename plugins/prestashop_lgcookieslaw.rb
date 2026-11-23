Plugin.define do
  name "EU Cookie Law GDPR (Banner + Blocker)"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the EU Cookie Law GDPR (Banner + Blocker) module (lgcookieslaw) for PrestaShop from the landing document. The module renders its front CSS/JavaScript asset references on every shop page; the release is not part of that response."
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
  ]
end
