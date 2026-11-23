Plugin.define do
  name "Gradio"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Gradio, the Python library for building machine-learning web apps, from the runtime markers every Gradio landing document carries in both client-side and server-side rendering modes."
  website "https://www.gradio.app"

  matches [
    {
      :search => "body",
      :regexp => /window\.__gradio_mode__[\s\S]{0,600}?gradio:iframe-resizer-ready/i,
      :name => "Gradio runtime markers",
    },
  ]
end
