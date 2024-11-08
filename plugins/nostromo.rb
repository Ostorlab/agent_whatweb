Plugin.define do
    name "Nostromo Server"
    authors [
      "Ostorlab",
    ]
    version "0.1"
    description "Nostromo is a lightweight, open-source web server designed for Unix-based systems, known for its simplicity and minimal resource usage."
    website "https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD"
  
    matches [
      {
        :search => "headers[server]",
        :regexp => /nostromo \d+\.\d+\.\d+/
      },
    ]
  end