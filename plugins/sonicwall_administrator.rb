Plugin.define do
  name "SonicWall Authentication"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Detects the SonicWall authentication page by looking for unique elements in the HTML."
  website "https://www.sonicwall.com/"
  matches [
    {
      :search => "head",
      :regexp => /<title>SonicWall - Authentication<\/title>/,
      :name => "SonicWall Title Tag"
    },
    {
      :search => "head",
      :regexp => /<meta name="SonicWall Administrator" content="Copyright 2004 \(c\) SonicWall, Inc. All rights reserved.">/,
      :name => "SonicWall Meta Tag"
    },
  ]
end
