source 'https://rubygems.org'

RONIN_URI = 'https://github.com/ronin-rb'

gemspec

gem 'jruby-openssl',	'~> 0.7', platforms: :jruby

# Ronin dependencies
gem 'ronin-support',  '~> 1.0', git: "#{RONIN_URI}/ronin-support.git",
                                branch: '1.0.0'

group :development do
  gem 'rake'
  gem 'rubygems-tasks', '~> 0.2'

  gem 'rspec',          '~> 3.0'
  gem 'simplecov',      '~> 0.20'

  gem 'kramdown',      '~> 2.0'
  gem 'redcarpet',       platform: :mri
  gem 'yard',           '~> 0.9'
  gem 'yard-spellcheck', require: false

  gem 'dead_end', require: false
end
