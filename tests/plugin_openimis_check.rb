# Behavioral check for the openIMIS plugin's landing marker.
#
# Usage: ruby plugin_openimis_check.rb <plugins directory>
# Exits 1 if a genuine openIMIS landing does not match or a lookalike does.

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

REAL_LANDING = <<~HTML
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <link rel="shortcut icon" href="/favicon.ico" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <meta name="theme-color" content="#000000" />
      <link rel="manifest" href="/manifest.json" />
      <title>openIMIS</title>
    </head>
    <body>
      <div id="root"></div>
    </body>
  </html>
HTML

LOOKALIKE = <<~HTML
  <html><head><title>openIMIS clone</title></head><body>lookalike</body></html>
HTML

UNRELATED = <<~HTML
  <html><head><title>Insurance management</title></head><body>other product</body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "openimis.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "real landing did not match" unless body_matched?(body_patterns, REAL_LANDING)
if body_matched?(body_patterns, LOOKALIKE)
  failures << "lookalike matched"
end
if body_matched?(body_patterns, UNRELATED)
  failures << "unrelated landing matched"
end

if failures.empty?
  puts "openIMIS plugin markers OK"
else
  warn failures.join("\n")
  exit 1
end
