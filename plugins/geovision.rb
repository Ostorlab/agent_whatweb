Plugin.define do
    name "GeoVision"
    authors [
      "Ostorlab",
    ]
    version "0.1"
    description "GeoVision specializes in advanced video surveillance solutions, offering state-of-the-art IP cameras, cloud-based surveillance platforms. etc..."
    website "https://www.geovision.com.tw/"
  
    matches [
      {:text => "<img src=\"img/WebLogin/logo.png\""},
      {:regexp => /Geovision Inc./i},
      {:text => "<title>Geovision"}
    ]
  end
  