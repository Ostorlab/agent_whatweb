# Behavioral check for the Apache Roller plugin's product markers.
#
# Usage: ruby plugin_roller_check.rb <plugins directory>
# Exits 1 if a genuine Roller landing does not match or a lookalike does.

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

INSTALL_615 = <<~HTML
  <!doctype html>
  <html><head><title>Front Page: Welcome to Roller!</title>
  <link rel="stylesheet" media="all" href='/roller/roller-ui/styles/roller.css' />
  <script src="/roller/theme/scripts/roller.js"></script></head><body>
  <a class="navbar-brand" href="#">Roller Site</a>
  <a href="/roller/roller-ui/menu.rol">Main Menu</a>
  <h1 class="roller-page-title">Welcome to Roller!</h1>
  </body></html>
HTML

FRONT_615 = <<~HTML
  <!doctype html>
  <html><head><title>Ostorlab Blog</title></head><body>
  <a href="/roller/roller-ui/menu.rol">Main Menu</a>
  <div id="footer">Powered by
  <a href="http://roller.apache.org">Apache Roller</a> 6.1.5</div>
  </body></html>
HTML

SETUP_616 = <<~HTML
  <!doctype html>
  <html><head><title>Roller initial setup</title>
  <link rel="stylesheet" href="/roller/roller-ui/styles/roller.css" />
  <script src="/roller/theme/scripts/roller.js"></script></head><body>
  <a class="navbar-brand" href="#">Apache Roller</a>
  <h1>Secure initial setup</h1>
  </body></html>
HTML

GENERIC = <<~HTML
  <!doctype html><html><head><title>Unrelated dashboard</title></head>
  <body><p>Welcome to an unrelated service.</p></body></html>
HTML

ASSET_ONLY = <<~HTML
  <!doctype html><html><head><title>Unrelated</title>
  <link rel="stylesheet" href="/static/roller-ui/styles/roller.css" /></head>
  <body>nothing</body></html>
HTML

TEXT_ONLY = <<~HTML
  <!doctype html><html><head><title>Unrelated</title></head>
  <body>Apache Roller is mentioned here.</body></html>
HTML

FOOTER_ONLY = <<~HTML
  <!doctype html><html><head><title>Unrelated</title></head><body>
  <div id="footer">Powered by
  <a href="http://roller.apache.org">Apache Roller</a> 6.1.5</div>
  </body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "roller.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "6.1.5 setup page did not match" unless body_matched?(body_patterns, INSTALL_615)
failures << "6.1.5 front page did not match" unless body_matched?(body_patterns, FRONT_615)
failures << "6.1.6 setup page did not match" unless body_matched?(body_patterns, SETUP_616)
failures << "generic page matched" if body_matched?(body_patterns, GENERIC)
failures << "asset-only lookalike matched" if body_matched?(body_patterns, ASSET_ONLY)
failures << "text-only lookalike matched" if body_matched?(body_patterns, TEXT_ONLY)
failures << "footer-only lookalike matched" if body_matched?(body_patterns, FOOTER_ONLY)

version_match = body_patterns.lazy.map { |pattern| FRONT_615.match(pattern) }.find { |match| match && match[1] }
failures << "release was not captured" unless version_match && version_match[1] == "6.1.5"
footer_version = body_patterns.lazy.map { |pattern| FOOTER_ONLY.match(pattern) }.find { |match| match && match[1] }
failures << "footer-only lookalike captured a release" if footer_version

puts failures
exit(failures.empty? ? 0 : 1)
