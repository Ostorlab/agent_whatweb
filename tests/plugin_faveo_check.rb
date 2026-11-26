# Behavioral check for the Faveo Helpdesk guest-portal footer markers.
#
# Usage: ruby plugin_faveo_check.rb <plugins directory>
# Exits 1 if a genuine Faveo landing page does not match or a lookalike matches.

class Plugin
  @plugins = []
  ALLOWED = %i[name authors version description website dorks matches passive aggressive].freeze

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  ALLOWED.each do |attribute|
    define_method(attribute) do |value = nil|
      instance_variable_set("@#{attribute}", value) unless value.nil?
      instance_variable_get("@#{attribute}")
    end
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(name, *_args, &_block)
    raise NoMethodError, "unknown WhatWeb Plugin DSL attribute: #{name}"
  end

  def respond_to_missing?(_name, _include_private = false)
    ALLOWED.include?(_name)
  end
end

# Captured from the real Faveo Helpdesk 2.0.3 guest portal. The footer is the
# product's own shipped client layout, not the demo company data.
PRODUCT_LANDING = <<~HTML
  <!doctype html>
  <html>
  <head><title>SUPPORT CENTER</title>
  <!-- faveo favicon -->
  </head>
  <body>
  <div class="row">
    <div class="site-info col-md-6">
      <p class="text-muted">Copyright &copy; 2026
        <a href="" target="_blank">ABC Clothing</a>. All rights reserved.
        Powered by <a href="https://www.faveohelpdesk.com/"  target="_blank">Faveo</a></p>
    </div>
  </div>
  </body>
  </html>
HTML

# The 2.0.4.B.1 guest portal keeps the same footer; the fix is server-side.
PRODUCT_FIXED_LANDING = <<~HTML
  <!doctype html>
  <html><head><title>SUPPORT CENTER</title><!-- faveo favicon --></head>
  <body><footer><p>Powered by
    <a href="https://www.faveohelpdesk.com/" target="_blank">Faveo</a></p></footer>
  </body></html>
HTML

FAVICON_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Support</title>
  <!-- faveo favicon -->
  <link rel="shortcut icon" href="/favicon.ico">
  </head><body><h1>Support center</h1></body></html>
HTML

LINK_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Help desk comparison</title></head>
  <body><p>Compare <a href="https://www.faveohelpdesk.com/">Faveo</a> with other help desks.</p></body></html>
HTML

MENTION_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Faveo review</title></head>
  <body><h1>Faveo Helpdesk review</h1><p>A blog post about Faveo.</p></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "faveo.rb")
plugin = Plugin.plugins.last

def page_matched?(plugin, page)
  plugin.matches.any? do |match|
    next false if match[:url]

    hit = false
    hit ||= page.match?(match[:regexp]) if match[:regexp].is_a?(Regexp)
    hit ||= page.match?(match[:version]) if match[:version].is_a?(Regexp)
    hit ||= page.include?(match[:text]) if match[:text].is_a?(String)
    hit
  end
end

failures = []
failures << "2.0.3 landing did not match" unless page_matched?(plugin, PRODUCT_LANDING)
failures << "2.0.4.B.1 landing did not match" unless page_matched?(plugin, PRODUCT_FIXED_LANDING)
failures << "favicon-only lookalike matched" if page_matched?(plugin, FAVICON_ONLY_LOOKALIKE)
failures << "link-only lookalike matched" if page_matched?(plugin, LINK_ONLY_LOOKALIKE)
failures << "mention-only lookalike matched" if page_matched?(plugin, MENTION_LOOKALIKE)

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
