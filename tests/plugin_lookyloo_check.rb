# Behavioral check for the Lookyloo plugin's product-specific footer.
#
# Usage: ruby plugin_lookyloo_check.rb <plugins directory>
# Exits 1 if a genuine Lookyloo landing does not match or a lookalike does.

class Plugin
  @plugins = []

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  def name(value = nil)
    @name = value unless value.nil?
    @name
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(*_args, &_block)
    nil
  end

  def respond_to_missing?(*_args)
    true
  end
end

VULNERABLE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Lookyloo</title>
  <meta property="og:title" content="Lookyloo" /></head><body>
  <footer class="lk-footer">
    <p class="lk-footer-about">
      <strong>Lookyloo</strong> <span class="lk-footer-version">v1.43.1</span><br>
      Web forensics: capture a page in a real browser and see everything it loaded.
    </p>
    <ul class="lk-footer-links">
      <li><a href="https://github.com/Lookyloo/lookyloo/releases/tag/v1.43.1">Changelog</a></li>
    </ul>
  </footer>
  </body></html>
HTML

# The 1.43.2 tag still advertises the 1.43.1 package version.
FIXED = VULNERABLE

NEWER = VULNERABLE.sub("v1.43.1", "v1.44.0")

TITLE_ONLY = <<~HTML
  <!doctype html>
  <html><head><title>Lookyloo</title></head>
  <body>Lookyloo documentation and a mention of the product name.</body></html>
HTML

CLASS_ONLY = <<~HTML
  <!doctype html>
  <html><head><title>Dashboard</title></head><body>
  <footer><span class="lk-footer-version">v1.43.1</span></footer>
  </body></html>
HTML

BRAND_ONLY = <<~HTML
  <!doctype html>
  <html><head><title>Lookyloo</title></head><body>
  <footer><strong>Lookyloo</strong> web forensics</footer>
  </body></html>
HTML

UNRELATED = <<~HTML
  <!doctype html>
  <html><head><title>Other product</title></head><body>
  <footer><strong>Other</strong> <span class="footer-version">v2.0.0</span></footer>
  </body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "lookyloo.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "vulnerable Lookyloo landing did not match" unless body_matched?(body_patterns, VULNERABLE)
failures << "fixed Lookyloo landing did not match" unless body_matched?(body_patterns, FIXED)
failures << "newer Lookyloo landing did not match" unless body_matched?(body_patterns, NEWER)
failures << "title-only lookalike matched" if body_matched?(body_patterns, TITLE_ONLY)
failures << "footer-class-only lookalike matched" if body_matched?(body_patterns, CLASS_ONLY)
failures << "brand-only lookalike matched" if body_matched?(body_patterns, BRAND_ONLY)
failures << "unrelated page matched" if body_matched?(body_patterns, UNRELATED)

version_match = body_patterns.lazy.map { |pattern| VULNERABLE.match(pattern) }.find(&:itself)
failures << "release was not captured" unless version_match && version_match[1] == "1.43.1"

puts failures
exit(failures.empty? ? 0 : 1)
