# Behavioral check for the 53AIHub plugin's product-specific markers.
#
# Usage: ruby plugin_53aihub_check.rb <plugins directory>
# Exits 1 if a genuine 53AIHub landing does not match or a lookalike does.

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

FRONT_LANDING = <<~HTML
  <!doctype html>
  <html lang="zh-CN"><head>
  <meta charset="UTF-8" />
  <title> </title>
  <script>
    const pathname = location.pathname || location.hash
    if (pathname.includes('share/recording')) {
      document.title = '安心录'
    } else {
      document.title = '53AIKM'
    }
  </script>
  <script type="module" crossorigin src="/assets/main-CPMWH_Ew.js"></script>
  </head><body><div id="root"></div>
  <script>var hm = "https://hm.baidu.com/hm.js?c0e32ea294a4fc371fe6ec64187e36e1";</script>
  </body></html>
HTML

CONSOLE_LANDING = <<~HTML
  <!doctype html>
  <html lang="zh-CN"><head>
  <meta charset="UTF-8" />
  <title>53AI</title>
  </head><body><div id="root"></div>
  <script>var hm = "https://hm.baidu.com/hm.js?c0e32ea294a4fc371fe6ec64187e36e1";</script>
  </body></html>
HTML

TITLE_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>53AIKM</title></head>
  <body>53AIKM documentation and a mention of the product name.</body></html>
HTML

UNRELATED_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Knowledge base</title></head>
  <body><div id="root"></div><script src="/assets/app.js"></script></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "53aihub.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "real front landing did not match" unless body_matched?(body_patterns, FRONT_LANDING)
failures << "console landing did not match" unless body_matched?(body_patterns, CONSOLE_LANDING)
if body_matched?(body_patterns, TITLE_ONLY_LOOKALIKE)
  failures << "title-only lookalike matched"
end
if body_matched?(body_patterns, UNRELATED_LOOKALIKE)
  failures << "unrelated lookalike matched"
end

if failures.empty?
  puts "53AIHub plugin markers OK"
else
  warn failures.join("\n")
  exit 1
end
