Plugin.define do
  name "Ivanti vTM"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Ivanti finds, heals and protects every device, everywhere – automatically. Whether your team is down the hall or spread around the globe, Ivanti makes it easy and secure for them to do what they do best."
  website "https://www.ivanti.com/"

  matches [
    {
      :search => "body",
      :regexp => /<span class="product">Virtual Traffic Manager Appliance/,
      :name => "Ivanti vTM body Tag"
    },
  ]
end