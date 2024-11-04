Plugin.define do
  name "ValueHD PTZ Camera"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "A PTZOptics camera offers a flexible solution for recording and live streaming events due to its pan, tilt, and zoom abilities and high-quality image."
  website "https://www.ptzoptics.com/"

  matches [
    {
      :search => "body",
      :regexp => /<script type="text\/javascript" src="dist\/ptzomidi_v2\.js"><\/script>/,
      :name => "PTZOptics JavaScript file mentioned in the body of the page"
    }
  ]
end
